package passwordless

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"time"

	"context"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/securecookie"
)

var (
	ErrNoResponseWriter = errors.New("Context passed to CookieStore.Store " +
		"does not contain a ResponseWriter")
	ErrInvalidTokenUID = errors.New("invalid UID in token")
	ErrInvalidTokenPIN = errors.New("invalid PIN in token")
	ErrWrongTokenUID   = errors.New("wrong UID in token")
)

// CookieStore stores tokens in a encrypted cookie on the user's browser.
// This token is then decrypted and checked against the provided value to
// determine of the token is valid.
type CookieStore struct {
	sk   []byte
	cs   *securecookie.SecureCookie
	Path string
	Key  string
}

// NewCookieStore creates a new signed and encrypted CookieStore.
func NewCookieStore(signingKey, authKey, encrKey []byte) *CookieStore {
	return &CookieStore{
		Path: "/",
		Key:  "passwordless",
		sk:   signingKey,
		cs:   securecookie.New(authKey, encrKey),
	}
}

// Store encrypts and writes the token to the curent response.
//
// The cookie is set with an expiry equal to that of the token, but the token
// expiry *must* be validated on receipt.
//
// This function requires that a ResponseWriter is present in the context.
func (s *CookieStore) Store(ctx context.Context, token, uid string, ttl time.Duration) error {
	rw, _ := fromContext(ctx)
	if rw == nil {
		return ErrNoResponseWriter
	}

	// Create signed token
	exp := time.Now().Add(ttl)
	tokString, err := s.newToken(token, uid, exp)
	if err != nil {
		return err
	}

	// Encode and encrypt cookie value
	encoded, err := s.cs.Encode(s.Key, tokString)
	if err != nil {
		return err
	}

	// Emit cookie into response
	cookie := &http.Cookie{
		Expires: exp,
		MaxAge:  int(ttl / time.Second),
		Name:    s.Key,
		Value:   encoded,
		Path:    s.Path,
	}
	http.SetCookie(rw, cookie)

	return nil
}

func (s *CookieStore) Exists(ctx context.Context, uid string) (bool, time.Time, error) {
	// Read cookie
	_, req := fromContext(ctx)
	var cookie *http.Cookie
	var err error

	if cookie, err = req.Cookie(s.Key); err != nil {
		return false, time.Time{}, err
	}

	// Read JWT string from cookie
	var tokString string
	if err = s.cs.Decode(s.Key, cookie.Value, &tokString); err != nil {
		return false, time.Time{}, err
	}
	// Parse JWT string
	tok, claims, err := s.parseToken(tokString)

	// Reject invalid JWTs
	if err != nil || !tok.Valid {
		return false, time.Time{}, err
	}

	// Check token is for the same UID
	if u, ok := claims["uid"].(string); !ok {
		// Token contains bad UID
		return false, time.Time{}, ErrInvalidTokenUID
	} else if u != uid {
		// Token is for a different UID
		return false, time.Time{}, ErrWrongTokenUID
	}

	exp := time.Unix(int64(claims["exp"].(float64)), 0)
	return true, exp, nil
}

// Verify reads the cookie from the request and verifies it against the
// provided values, returning true on success.
func (s *CookieStore) Verify(ctx context.Context, pin, uid string) (bool, error) {
	_, req := fromContext(ctx)
	var cookie *http.Cookie
	var err error
	if cookie, err = req.Cookie(s.Key); err != nil {
		return false, err
	}

	var tokString string
	if err = s.cs.Decode(s.Key, cookie.Value, &tokString); err != nil {
		return false, err
	}

	return s.verifyToken(tokString, pin, uid)
}

// Delete deletes the cookie.
//
// This function requires that a ResponseWriter is present in the context.
func (s *CookieStore) Delete(ctx context.Context, uid string) error {
	rw, _ := fromContext(ctx)
	if rw == nil {
		return ErrNoResponseWriter
	}
	cookie := &http.Cookie{
		MaxAge: 0,
		Name:   s.Key,
		Path:   s.Path,
	}
	http.SetCookie(rw, cookie)
	return nil
}

// newToken creates and returns a new *unencrypted* JWT token containing the
// pin and user ID.
func (s *CookieStore) newToken(pin, uid string, exp time.Time) (string, error) {
	tok := jwt.New(jwt.SigningMethodHS256)
	tok.Claims = jwt.MapClaims{
		"exp": exp.Unix(),
		"uid": uid,
		"pin": pin,
	}
	return tok.SignedString(s.sk)
}

// parseToken parses the token stored in the given strinng.
func (s *CookieStore) parseToken(t string) (*jwt.Token, jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(t, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("verifyToken: unexpected signing method %s", token.Header["alg"])
		}
		return s.sk, nil
	})
	return tok, claims, err
}

// verifyToken verifies an *unencrypted* JWT token.
func (s *CookieStore) verifyToken(t, pin, uid string) (bool, error) {
	tok, claims, err := s.parseToken(t)

	// Reject invalid JWTs
	if err != nil || !tok.Valid {
		return false, err
	}

	// Check token matches supplied data.
	if u, ok := claims["uid"].(string); !ok {
		return false, ErrInvalidTokenUID
	} else if p, ok := claims["pin"].(string); !ok {
		return false, ErrInvalidTokenPIN
	} else {
		validUID := (u == uid)
		validPIN := (1 == subtle.ConstantTimeCompare([]byte(p), []byte(pin)))
		return validUID && validPIN, nil
	}
}
