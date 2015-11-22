package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"bitbucket.org/johnsto/go-passwordless"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
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

	baseURL = "http://localhost:8080"
	store = sessions.NewCookieStore([]byte("my insecure key!"))

	// Passwordless: init with ephemeral memory store and two handlers
	//tokStore := passwordless.NewMemStore()
	tokStore := passwordless.NewCookieStore(
		[]byte("abracadabrawizzy"), // signing key
		[]byte("authenticatorkey"), // auth key
		[]byte("theencryptionkey")) // encryption key
	pw = passwordless.New(tokStore)
	pw.SetTransport("email", passwordless.LogTransport{
		MessageFunc: func(token, uid string) string {
			return fmt.Sprintf("Login at %s/account/verify?token=%s&uid=%s",
				baseURL, token, uid)
		},
	}, passwordless.NewCrockfordGenerator(12), 30*time.Minute)
	pw.SetTransport("sms", passwordless.LogTransport{
		MessageFunc: func(token, uid string) string {
			return fmt.Sprintf("Your PIN is %s", token)
		},
	}, passwordless.PINGenerator{6}, 30*time.Minute)

	// Setup routes
	http.HandleFunc("/", tmplHandler("index"))
	http.HandleFunc("/about", tmplHandler("about"))
	http.HandleFunc("/guide", tmplHandler("guide"))

	// Setup signin/out routes
	http.HandleFunc("/account/signin", signinHandler)
	http.HandleFunc("/account/token", tokenHandler)
	http.HandleFunc("/account/signout", signoutHandler)

	// Setup restricted routes that require a valid username
	restricted := http.NewServeMux()
	http.HandleFunc("/restricted", RestrictedHandler(
		baseURL+"/account/signin", restricted))
	restricted.HandleFunc("/", secretHandler)

	// Listen!
	log.Fatal(http.ListenAndServe(":8080",
		context.ClearHandler(http.DefaultServeMux)))
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

func secretHandler(w http.ResponseWriter, r *http.Request) {
	if session, err := getSession(w, r); err == nil {
		tmpl.ExecuteTemplate(w, "secret", struct {
			Context *Context
		}{
			Context: getTemplateContext(w, r, session),
		})
	}
}
