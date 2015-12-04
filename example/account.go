package main

import (
	"log"
	"net/http"

	"bitbucket.org/johnsto/go-passwordless"
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
// token they input, and redirects them approriately on success. On failure,
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

	log.Println("strategy:", strategy, "recipient:", recipient,
		"uid: ", uid, "token:", token)

	if uid == "" {
		// Lookup user ID. We just use the recipient in this demo.
		uid = recipient
	}

	if token == "" {
		// No token provided, so send one to the user.
		log.Println("Sending token")
		if err := pw.RequestToken(ctx, strategy, uid, recipient); err != nil {
			log.Println("Error sending token", err)
			writeError(w, r, session, http.StatusInternalServerError, Error{
				Name:        "Internal Error",
				Description: err.Error(),
				Error:       err,
			})
			return
		}
		log.Println("Token sent")
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
			// Token not found, maybe it was a previous one.
			session.AddFlash("token_not_found")
			http.Redirect(w, r, "/account/signin", http.StatusTemporaryRedirect)
			return
		} else if err != nil {
			// Some other unexpected error!
			writeError(w, r, session, http.StatusInternalServerError, Error{
				Name:        "Failed verifying token",
				Description: err.Error(),
				Error:       err,
			})
			return
		} else {
			// User entered bad token. Set token then fall through to template.
			w.WriteHeader(http.StatusForbidden)
			tokenError = "The entered token/PIN was incorrect."
		}
	}

	log.Println("Writing response")
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
