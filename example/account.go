package main

import (
	"log"
	"net/http"

	"github.com/johnsto/go-passwordless/v2"
)

// signinHandler prompts the user to choose a method by which to send them
// a token.
func signinHandler(w http.ResponseWriter, r *http.Request) {
	if session, err := getSession(w, r); err == nil {
		if isSignedIn(session) {
			session.AddFlash("already_signed_in")
			session.Save(r, w)
			redirect(w, r, "/", baseURL)
			return
		}

		if err := tmpl.ExecuteTemplate(w, "signin", struct {
			Strategies map[string]passwordless.Strategy
			Context    *Context
			Next       string
		}{
			Strategies: pw.ListStrategies(nil),
			Context:    getTemplateContext(w, r, session),
			Next:       r.FormValue("next"),
		}); err != nil {
			log.Println(err)
		}
	}
}

// tokenHandler has two roles. Firstly, it allows the user to input the token
// they have received via their chosen method. Secondly, it verifies the
// token they input, and redirects them appropriately on success. On failure,
// the user is prompted to try again.
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(w, r)
	if err != nil {
		log.Println(err)
		return
	}

	if isSignedIn(session) {
		session.AddFlash("already_signed_in")
		session.Save(r, w)
		redirect(w, r, r.FormValue("next"), baseURL)
		return
	}

	// Create a context (required by CookieStore token store)
	ctx := passwordless.SetContext(nil, w, r)

	strategy := r.FormValue("strategy")
	recipient := r.FormValue("recipient")
	uid := r.FormValue("uid")

	// token is only set if the user is trying to verify a token they've got
	token := r.FormValue("token")

	// tokenError will be set if the user enters a bad token.
	tokenError := ""

	if uid == "" {
		// Lookup user ID. We just use the recipient value in this demo,
		// but typically you'd perform a database query here.
		uid = recipient
	}

	log.Println("strategy=", strategy, "recipient=", recipient, "uid=", uid, "token=", token)

	if strategy == "" {
		// No strategy specified in request, so send the user back to
		// the signin page as we can't do anything without it.
		session.AddFlash("token_not_found")
		session.Save(r, w)
		http.Redirect(w, r, "/account/signin", http.StatusTemporaryRedirect)
		return
	} else if token == "" {
		// No token provided in request, so generate a new one and send it
		// to the user via their preferred transport strategy.
		err := pw.RequestToken(ctx, strategy, uid, recipient)

		if err != nil {
			writeError(w, r, session, http.StatusInternalServerError, Error{
				Name:        "Internal Error",
				Description: err.Error(),
				Error:       err,
			})
			return
		}
	} else {
		// User has provided a token, verify it against provided uid.
		valid, err := pw.VerifyToken(ctx, uid, token)

		if valid {
			// User provided a valid token! We can safely use the uid as it
			// is validated alongside the token.
			session.Values["uid"] = uid
			session.AddFlash("signed_in")
			session.Save(r, w)
			redirect(w, r, r.FormValue("next"), baseURL)
			return
		}

		if err == passwordless.ErrTokenNotFound {
			// Token not found, maybe it was a previous one or expired. Either
			// way, the user will need to attempt sign-in again.
			session.AddFlash("token_not_found")
			session.Save(r, w)
			http.Redirect(w, r, "/account/signin", http.StatusTemporaryRedirect)
			return
		} else if err != nil {
			// Some other unexpected error occurred.
			writeError(w, r, session, http.StatusInternalServerError, Error{
				Name:        "Failed verifying token",
				Description: err.Error(),
				Error:       err,
			})
			return
		} else {
			// User entered bad token. Set token error string then fall
			// through to template.
			w.WriteHeader(http.StatusForbidden)
			tokenError = "The entered token/PIN was incorrect."
		}
	}

	// If we've got to this point, the user is being prompted to enter a
	// valid token value.
	if err := tmpl.ExecuteTemplate(w, "token", struct {
		Context    *Context
		Strategy   string
		Recipient  string
		UserID     string
		Next       string
		TokenError string
	}{
		Strategy:   strategy,
		Recipient:  recipient,
		UserID:     uid,
		Context:    getTemplateContext(w, r, session),
		Next:       r.FormValue("next"),
		TokenError: tokenError,
	}); err != nil {
		log.Printf("couldn't render template: %v", err)
	}
}

func signoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(w, r)
	if err != nil {
		return
	}

	// Remove secure session cookie
	delete(session.Values, "uid")
	session.AddFlash("signed_out")
	session.Save(r, w)

	redirect(w, r, r.FormValue("next"), baseURL)
}
