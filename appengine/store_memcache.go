package appengine

import (
	"time"

	"github.com/johnsto/go-passwordless/v2"

	"context"

	"github.com/gyepisam/mcf"
	_ "github.com/gyepisam/mcf/scrypt"
	"google.golang.org/appengine/memcache"
)

type MemcacheStore struct {
	KeyPrefix string
}

type item struct {
	hashToken string    `json:"token"`
	expiresAt time.Time `json:"expires_at"`
}

func (s MemcacheStore) Store(ctx context.Context, token, uid string, ttl time.Duration) error {
	hashToken, err := mcf.Create(token)
	if err != nil {
		return err
	}

	expiresAt := time.Now().Add(ttl)
	return memcache.JSON.Set(ctx, &memcache.Item{
		Key:        s.KeyPrefix + uid,
		Object:     item{hashToken, expiresAt},
		Expiration: ttl,
	})
}

// Exists returns true if a token for the specified user exists.
func (s MemcacheStore) Exists(ctx context.Context, uid string) (bool, time.Time, error) {
	v := item{}
	_, err := memcache.JSON.Get(ctx, s.KeyPrefix+uid, &v)
	if err == memcache.ErrCacheMiss {
		// No known token for this user
		return false, time.Time{}, nil
	} else {
		// Token exists and is still valid
		return true, v.expiresAt, nil
	}
}

func (s MemcacheStore) Verify(ctx context.Context, token, uid string) (bool, error) {
	v := item{}
	_, err := memcache.JSON.Get(ctx, s.KeyPrefix+uid, &v)
	if err == memcache.ErrCacheMiss {
		// No token in database
		return false, passwordless.ErrTokenNotFound
	} else if err != nil {
		return false, err
	}

	if time.Now().After(v.expiresAt) {
		// Token has actually expired (even if still present in memcache)
		return false, passwordless.ErrTokenNotFound
	} else if valid, err := mcf.Verify(token, v.hashToken); err != nil {
		// Couldn't validate token
		return false, err
	} else if !valid {
		// Token does not validate against hashed token
		return false, nil
	} else {
		// Token is valid!
		return true, nil
	}
}

func (s MemcacheStore) Delete(ctx context.Context, uid string) error {
	return memcache.Delete(ctx, s.KeyPrefix+uid)
}
