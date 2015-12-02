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

	"bitbucket.org/johnsto/go-passwordless"
	gcontext "github.com/gorilla/context"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/net/context"
)

var pw *passwordless.Passwordless

var (
	tmpl    *template.Template
	store   sessions.Store
	baseURL string
)

func main() {
	var err error
	tmpl, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalln(err)
	}

	baseURL = os.Getenv("PWL_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
		log.Printf("PWL_BASE_URL not defined; using %s", baseURL)
	}

	cookieKey := []byte(os.Getenv("PWL_KEY_COOKIE_STORE"))
	if len(cookieKey) == 0 {
		log.Println("PWL_KEY_COOKIE_STORE not defined; using random key")
		cookieKey = securecookie.GenerateRandomKey(16)
	}

	store = sessions.NewCookieStore(cookieKey)

	// Passwordless: init with ephemeral memory store and two handlers
	tokStore := passwordless.NewMemStore()
	pw = passwordless.New(tokStore)
	pw.SetTransport("email", passwordless.NewSMTPTransport(
		os.Getenv("PWL_EMAIL_ADDR"),
		os.Getenv("PWL_EMAIL_FROM"),
		"Your go-passwordless login link",
		smtp.PlainAuth(
			os.Getenv("PWL_EMAIL_AUTH_IDENTITY"),
			os.Getenv("PWL_EMAIL_AUTH_USERNAME"),
			os.Getenv("PWL_EMAIL_AUTH_PASSWORD"),
			os.Getenv("PWL_EMAIL_AUTH_HOST")),
		func(ctx context.Context, token, recipient string, w io.Writer) error {
			e := passwordless.Email{Subject: "test"}
			e.SetBody("", "hello")
			_, err := e.Write(w)
			return err
		},
	), passwordless.NewCrockfordGenerator(4), 30*time.Minute)
	/*pw.SetTransport("debug", passwordless.LogTransport{
		MessageFunc: func(token, uid string) string {
			return fmt.Sprintf("Login at %s/account/verify?token=%s&uid=%s",
				baseURL, token, uid)
		},
	}, passwordless.NewCrockfordGenerator(4), 30*time.Minute)*/

	// Setup routes
	http.HandleFunc("/", tmplHandler("index"))
	http.HandleFunc("/about", tmplHandler("about"))
	http.HandleFunc("/guide", tmplHandler("guide"))

	// Setup signin/out routes
	http.HandleFunc("/account/signin", signinHandler)
	// FIXME: tokenHandler should be rate-limited to reduce susceptibility to
	// brute-force attacks. See `gopkg.in/throttled/throttled.v2`
	http.HandleFunc("/account/token", tokenHandler)
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
		log.Fatalln(err)
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
				return
			}
			h.ServeHTTP(w, r)
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
