package passwordless

import (
	"context"
	"time"

	"github.com/go-redis/redis/v7"
	"github.com/pzduniak/mcf"
)

const (
	redisPrefix = "passwordless-token::"
)

// RedisStore is a Store that keeps tokens in Redis.
type RedisStore struct {
	client redis.UniversalClient
}

// NewRedisStore creates and returns a new `RedisStore`.
func NewRedisStore(client redis.UniversalClient) *RedisStore {
	return &RedisStore{
		client: client,
	}
}

func redisKey(uid string) string {
	return redisPrefix + uid
}

// Store a generated token in redis for a user.
func (s RedisStore) Store(ctx context.Context, token, uid string, ttl time.Duration) error {
	hashToken, err := mcf.Create([]byte(token))
	if err != nil {
		return err
	}
	r := s.client.Set(redisKey(uid), hashToken, ttl)
	if r.Err() != nil {
		return err
	}

	return nil
}

// Exists checks to see if a token exists.
func (s RedisStore) Exists(ctx context.Context, uid string) (bool, time.Time, error) {
	dur, err := s.client.TTL(redisKey(uid)).Result()
	if err != nil {
		if err == redis.Nil {
			return false, time.Time{}, nil
		}
		return false, time.Time{}, err
	}
	expiry := time.Now().Add(dur)
	if time.Now().After(expiry) {
		return false, time.Time{}, nil
	}
	return true, expiry, nil
}

// Verify checks to see if a token exists and is valid for a user.
func (s RedisStore) Verify(ctx context.Context, token, uid string) (bool, error) {
	r, err := s.client.Get(redisKey(uid)).Result()
	if err != nil {
		if err == redis.Nil {
			return false, ErrTokenNotFound
		}
		return false, err
	}
	valid, err := mcf.Verify([]byte(token), []byte(r))
	if err != nil {
		return false, err
	}
	if !valid {
		return false, nil
	}
	return true, nil
}

// Delete removes a key from the store.
func (s RedisStore) Delete(ctx context.Context, uid string) error {
	_, err := s.client.Del(redisKey(uid)).Result()
	if err != nil {
		return err
	}
	return nil
}
