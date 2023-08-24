package passwordless

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
)

type rval struct {
	v string
	d time.Duration
}

type redisMock struct {
	redis.UniversalClient
	store map[string]rval
}

func newRedisMock() *redisMock {
	return &redisMock{
		store: map[string]rval{},
	}
}

func (r redisMock) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	val := rval{
		d: expiration,
	}
	switch v := value.(type) {
	case []byte:
		val.v = string(v)
	}
	r.store[key] = val
	return redis.NewStatusResult(key, nil)
}

func (r redisMock) TTL(ctx context.Context, key string) *redis.DurationCmd {
	v, ok := r.store[key]
	if !ok {
		return redis.NewDurationResult(-1*time.Second, nil)
	}
	cmd := redis.NewDurationResult(v.d, nil)
	return cmd
}

func (r redisMock) Get(ctx context.Context, key string) *redis.StringCmd {
	v, ok := r.store[key]
	if !ok {
		return redis.NewStringResult("", redis.Nil)
	}
	if time.Now().After(time.Now().Add(v.d)) {
		delete(r.store, key)
		return redis.NewStringResult("", redis.Nil)
	}
	return redis.NewStringResult(v.v, nil)
}

func (r redisMock) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	for _, k := range keys {
		delete(r.store, k)
	}
	return redis.NewIntResult(1, nil)
}

func TestRedisStore(t *testing.T) {
	ctx := context.TODO()
	ms := NewRedisStore(newRedisMock())
	assert.NotNil(t, ms)

	b, exp, err := ms.Exists(ctx, "uid")
	assert.False(t, b)
	assert.True(t, exp.IsZero())
	assert.NoError(t, err)

	err = ms.Store(ctx, "", "uid", -time.Hour)
	assert.NoError(t, err)
	b, exp, err = ms.Exists(ctx, "uid")
	assert.False(t, b)
	assert.True(t, exp.IsZero())
	assert.NoError(t, err)

	err = ms.Store(ctx, "", "uid", time.Hour)
	assert.NoError(t, err)
	b, exp, err = ms.Exists(ctx, "uid")
	log.Println(b, exp, err)
	assert.True(t, b)
	assert.False(t, exp.IsZero())
}

func TestRedisStoreVerify(t *testing.T) {
	ctx := context.TODO()
	ms := NewRedisStore(newRedisMock())
	assert.NotNil(t, ms)

	// Token doesn't exist
	b, err := ms.Verify(ctx, "badtoken", "uid")
	assert.False(t, b)
	assert.Equal(t, ErrTokenNotFound, err)

	// Token expired
	err = ms.Store(ctx, "", "uid", -time.Hour)
	assert.NoError(t, err)
	b, err = ms.Verify(ctx, "badtoken", "uid")
	assert.False(t, b)
	assert.Equal(t, ErrTokenNotFound, err)

	// Token wrong
	err = ms.Store(ctx, "token", "uid", time.Hour)
	assert.NoError(t, err)
	b, err = ms.Verify(ctx, "badtoken", "uid")
	assert.False(t, b)
	assert.NoError(t, err)

	// Token correct
	b, err = ms.Verify(ctx, "token", "uid")
	assert.True(t, b)
	assert.NoError(t, err)
}
