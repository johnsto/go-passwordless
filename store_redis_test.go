package passwordless

import (
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

func (r redisMock) Set(key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
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

func (r redisMock) TTL(key string) *redis.DurationCmd {
	v, ok := r.store[key]
	if !ok {
		return redis.NewDurationResult(-1*time.Second, nil)
	}
	cmd := redis.NewDurationResult(v.d, nil)
	return cmd
}

func (r redisMock) Get(key string) *redis.StringCmd {
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

func (r redisMock) Del(keys ...string) *redis.IntCmd {
	for _, k := range keys {
		delete(r.store, k)
	}
	return redis.NewIntResult(1, nil)
}

func TestRedisStore(t *testing.T) {
	ms := NewRedisStore(newRedisMock())
	assert.NotNil(t, ms)

	b, exp, err := ms.Exists(nil, "uid")
	assert.False(t, b)
	assert.True(t, exp.IsZero())
	assert.NoError(t, err)

	err = ms.Store(nil, "", "uid", -time.Hour)
	b, exp, err = ms.Exists(nil, "uid")
	assert.False(t, b)
	assert.True(t, exp.IsZero())
	assert.NoError(t, err)

	err = ms.Store(nil, "", "uid", time.Hour)
	b, exp, err = ms.Exists(nil, "uid")
	log.Println(b, exp, err)
	assert.True(t, b)
	assert.False(t, exp.IsZero())
}

func TestRedisStoreVerify(t *testing.T) {
	ms := NewRedisStore(newRedisMock())
	assert.NotNil(t, ms)

	// Token doesn't exist
	b, err := ms.Verify(nil, "badtoken", "uid")
	assert.False(t, b)
	assert.Equal(t, ErrTokenNotFound, err)

	// Token expired
	err = ms.Store(nil, "", "uid", -time.Hour)
	b, err = ms.Verify(nil, "badtoken", "uid")
	assert.False(t, b)
	assert.Equal(t, ErrTokenNotFound, err)

	// Token wrong
	err = ms.Store(nil, "token", "uid", time.Hour)
	b, err = ms.Verify(nil, "badtoken", "uid")
	assert.False(t, b)
	assert.NoError(t, err)

	// Token correct
	b, err = ms.Verify(nil, "token", "uid")
	assert.True(t, b)
	assert.NoError(t, err)
}
