package passwordless

import (
	"errors"
	"time"

	"golang.org/x/net/context"

	_ "github.com/gyepisam/mcf/scrypt"
)

var (
	ErrTokenNotFound = errors.New("the token does not exist")
	ErrTokenExpired  = errors.New("the token has expired")
	ErrTokenNotValid = errors.New("the token is incorrect")
)

// TokenStore is a storage mechanism for tokens.
type TokenStore interface {
	// Store securely stores the given token with the given expiry time
	Store(ctx context.Context, token, uid string, ttl time.Duration) error
	// Verify returns true if the given token is valid for the user
	Verify(ctx context.Context, token, uid string) (bool, error)
	// Delete removes the token for the specified  user
	Delete(ctx context.Context, uid string) error
}
