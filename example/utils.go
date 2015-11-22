package main

import (
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/sessions"
)

// Context holds data pertaining to the base page template.
type Context struct {
	SignedIn bool
	UserID   string
	UserName string
	Flashes  []interface{}
}

// Error represents an error that is displayed to the user.
type Error struct {
	Name        string
	Description string
	Error       error
}

// getTemplateContext returns a Context object containing the current user
// and other variables required by all templates.
func getTemplateContext(w http.ResponseWriter, r *http.Request, s *sessions.Session) *Context {
	ctx := &Context{
		Flashes: s.Flashes(),
	}
	if uid, ok := s.Values["uid"].(string); ok {
		ctx.SignedIn = true
		ctx.UserName = uid
		ctx.UserID = uid
	}
	s.Save(r, w)
	return ctx
}

// redirect is a helper method that issues a redirect to the client for the
// specified URL. If the URL is invalid, or for a different host, the client
// is redirected to the base URL instead.
func redirect(w http.ResponseWriter, r *http.Request, next, base string) {
	if nextURL, err := url.Parse(next); err != nil {
		log.Println("couldn't parse redirect URL " + next)
		next = base
	} else if nextURL.IsAbs() && next[:len(base)] != base {
		log.Println("redirect URL is not permitted: " + next)
		next = base
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// writeError is a helper method that emits an error page with the given status
// and session.
func writeError(w http.ResponseWriter, r *http.Request, s *sessions.Session, status int, e Error) {
	w.WriteHeader(status)
	tmpl.ExecuteTemplate(w, "error", struct {
		Context *Context
		Error   Error
	}{
		Context: getTemplateContext(w, r, s),
		Error:   e,
	})
}

// getSession is a helper method that gets a user session, or emits an
// appropriate error page (and returns the error) on failure.
func getSession(w http.ResponseWriter, r *http.Request) (*sessions.Session, error) {
	session, err := store.Get(r, "passwordless-example")
	if err != nil {
		writeError(w, r, session, http.StatusUnauthorized, Error{
			Name:        "Couldn't get session",
			Description: err.Error(),
			Error:       err,
		})
		return nil, err
	}
	return session, err
}

func isSignedIn(s *sessions.Session) bool {
	return s != nil && s.Values["uid"] != nil
}
