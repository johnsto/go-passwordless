package passwordless

import (
	"errors"
	"time"

	"golang.org/x/net/context"

	_ "github.com/gyepisam/mcf/scrypt"
)

var (
	ErrTokenNotFound = errors.New("the token does not exist")
	ErrTokenNotValid = errors.New("the token is incorrect")
)

// TokenStore is a storage mechanism for tokens.
type TokenStore interface {
	// Store securely stores the given token with the given expiry time
	Store(ctx context.Context, token, uid string, ttl time.Duration) error
	// Exists returns true if a token is stored for the user. If the expiry
	// time is available this is also returned, otherwise it will be zero
	// and can be tested with `Time.IsZero()`.
	Exists(ctx context.Context, uid string) (bool, time.Time, error)
	// Verify returns true if the given token is valid for the user
	Verify(ctx context.Context, token, uid string) (bool, error)
	// Delete removes the token for the specified  user
	Delete(ctx context.Context, uid string) error
}
