package passwordless

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSessionStoreToken(t *testing.T) {
	now := time.Now()
	cs := NewCookieStore([]byte{}, []byte{}, []byte{})

	valid, err := cs.verifyToken("", "1337", "userid")
	assert.Error(t, err)
	assert.False(t, valid)

	tok, err := cs.newToken("1337", "userid", now.Add(time.Hour))
	assert.NoError(t, err)

	valid, err = cs.verifyToken(tok, "1337", "userid")
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = cs.verifyToken(tok, "1338", "userid")
	assert.NoError(t, err)
	assert.False(t, valid)

	valid, err = cs.verifyToken(tok, "1337", "userie")
	assert.NoError(t, err)
	assert.False(t, valid)

	valid, err = cs.verifyToken(tok+" ", "1337", "userid")
	assert.Error(t, err)
	assert.False(t, valid)

	// Check token expiry
	tok, err = cs.newToken("1337", "userid", now.Add(-time.Hour))
	assert.NoError(t, err, "negative TTL should not fail")
	valid, err = cs.verifyToken(tok, "1337", "userid")
	assert.Error(t, err, "expired should produce error")
	assert.False(t, valid, "expired should not validate")
}
