package main

import (
	"html/template"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"time"

	"context"

	gcontext "github.com/gorilla/context"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/johnsto/go-passwordless"
	"gopkg.in/throttled/throttled.v2"
	"gopkg.in/throttled/throttled.v2/store/memstore"
)

const SesssionKey string = "go-passwordless-example"

var pw *passwordless.Passwordless

var (
	tmpl  *template.Template
	store sessions.Store
	// baseURL should contain the root URL of the web server
	baseURL string
)

func main() {
	var err error

	// Read templates
	tmpl, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalln("couldn't load templates:", err)
	}

	// Determine base URL
	baseURL = os.Getenv("PWL_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
		log.Printf("PWL_BASE_URL not defined; using %s", baseURL)
	}

	// Initialise cookie store, to store user credentials once they've
	// signed in through Passwordless.
	cookieKey := []byte(os.Getenv("PWL_KEY_COOKIE_STORE"))
	if len(cookieKey) == 0 {
		log.Println("PWL_KEY_COOKIE_STORE not defined; using random key")
		cookieKey = securecookie.GenerateRandomKey(16)
	}
	store = sessions.NewCookieStore(cookieKey)

	// Init Passwordless with ephemeral memory store that will hold tokens
	// util they're used (or expire)
	tokStore := passwordless.NewMemStore()
	pw = passwordless.New(tokStore)

	// Add Passwordless email transport using SMTP credentials from env
	pw.SetTransport("email", passwordless.NewSMTPTransport(
		os.Getenv("PWL_EMAIL_ADDR"),
		os.Getenv("PWL_EMAIL_FROM"),
		smtp.PlainAuth(
			os.Getenv("PWL_EMAIL_AUTH_IDENTITY"),
			os.Getenv("PWL_EMAIL_AUTH_USERNAME"),
			os.Getenv("PWL_EMAIL_AUTH_PASSWORD"),
			os.Getenv("PWL_EMAIL_AUTH_HOST")),
		emailWriter,
	), passwordless.NewCrockfordGenerator(10), 30*time.Minute)

	// Add debug handler, which prints message to stdout.
	/*pw.SetTransport("debug", passwordless.LogTransport{
		MessageFunc: func(token, uid string) string {
			return fmt.Sprintf("Login at %s/account/verify?token=%s&uid=%s",
				baseURL, token, uid)
		},
	}, passwordless.NewCrockfordGenerator(4), 30*time.Minute)*/

	limiter, err := rateLimiter()
	if err != nil {
		log.Fatalln(err)
	}

	// Setup routes
	http.HandleFunc("/", tmplHandler("index"))

	// Setup signin/out routes
	http.HandleFunc("/account/signin", signinHandler)
	http.Handle("/account/token",
		limiter.RateLimit(http.HandlerFunc(tokenHandler)))
	http.HandleFunc("/account/signout", signoutHandler)

	// Setup restricted routes that require a valid username
	restricted := http.NewServeMux()
	http.HandleFunc("/restricted", RestrictedHandler(
		baseURL+"/account/signin", restricted))
	restricted.HandleFunc("/", tmplHandler("secret"))

	// Listen!
	log.Fatal(http.ListenAndServe(":8080",
		gcontext.ClearHandler(http.DefaultServeMux)))
}

// RestrictedHandler wraps handlers and redirects the client to the specified
// signinUrl if they have not logged in.
func RestrictedHandler(signinUrl string, h http.Handler) func(http.ResponseWriter, *http.Request) {
	if _, err := url.Parse(signinUrl); err != nil {
		log.Fatalln("RestrictedHandler: signinUrl is not a valid URL", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if session, err := getSession(w, r); err == nil {
			if session.Values["uid"] == nil {
				// Not logged in, redirect to signin page with a redirect.
				u, _ := url.Parse(signinUrl)
				u.RawQuery = u.RawQuery + "&next=" + r.URL.String()
				session.AddFlash("forbidden")
				session.Save(r, w)
				http.Redirect(w, r, u.String(), http.StatusSeeOther)
			} else {
				// Logged in, fall through to original handler
				h.ServeHTTP(w, r)
			}
		}
	})
}

// tmplHandler returns a Handler that executes the named template.
func tmplHandler(name string) func(http.ResponseWriter, *http.Request) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if session, err := getSession(w, r); err == nil {
			tmpl.ExecuteTemplate(w, name, struct {
				Context *Context
			}{
				Context: getTemplateContext(w, r, session),
			})
		}
	})
}

// emailWriter writes the token to email form.
func emailWriter(ctx context.Context, token, uid, recipient string, w io.Writer) error {
	e := &passwordless.Email{
		Subject: "Go-Passwordless signin",
		To:      recipient,
	}

	link := baseURL + "/account/token" +
		"?strategy=email&token=" + token + "&uid=" + uid

	// Ideally these would be populated from templates, but...
	text := "You (or someone who knows your email address) wants " +
		"to sign in to the Go-Passwordless website.\n\n" +
		"Your PIN is " + token + " - or use the following link: " +
		link + "\n\n" +
		"(If you were did not request or were not expecting this email, " +
		"you can safely ignore it.)"
	html := "<!doctype html><html><body>" +
		"<p>You (or someone who knows your email address) wants " +
		"to sign in to the Go-Passwordless website.</p>" +
		"<p>Your PIN is <b>" + token + "</b> - or <a href=\"" + link + "\">" +
		"click here</a> to sign in automatically.</p>" +
		"<p>(If you did not request or were not expecting this email, " +
		"you can safely ignore it.)</p></body></html>"

	// Add content types, from least- to most-preferable.
	e.AddBody("text/plain", text)
	e.AddBody("text/html", html)

	_, err := e.Write(w)

	return err
}

// rateLimiter creates and returns a new HTTPRateLimiter
func rateLimiter() (*throttled.HTTPRateLimiter, error) {
	store, err := memstore.New(0x10000)
	if err != nil {
		return nil, err
	}

	quota := throttled.RateQuota{throttled.PerMin(10), 5}

	rateLimiter, err := throttled.NewGCRARateLimiter(store, quota)
	if err != nil {
		return nil, err
	}

	return &throttled.HTTPRateLimiter{
		RateLimiter: rateLimiter,
	}, nil
}
