package passwordless

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMemStore(t *testing.T) {
	ms := NewMemStore()
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
	assert.True(t, b)
	assert.False(t, exp.IsZero())
	assert.NoError(t, err)

	// Test keys are expired correctly
	err = ms.Store(nil, "", "expuid", time.Second)
	assert.NoError(t, err)
	b, _, _ = ms.Exists(nil, "expuid")
	assert.True(t, b)
	time.Sleep(time.Second)
	ms.Clean()
	b, _, _ = ms.Exists(nil, "expuid")
	assert.False(t, b)

	// Clean up
	ms.Release()
	time.Sleep(2 * time.Second)
}

func TestMemStoreVerify(t *testing.T) {
	ms := NewMemStore()
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
