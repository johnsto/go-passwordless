package passwordless

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
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

func TestSessionStoreExists(t *testing.T) {
	cs := NewCookieStore([]byte(""), []byte(""), []byte("testtesttesttest"))

	// Fail when attempting to Store with bad context
	err := cs.Store(nil, "", "", time.Hour)
	assert.Equal(t, err, ErrNoResponseWriter)

	// Fail when attempting to Verify without valid cookie
	req, err := http.NewRequest("", "", nil)
	v, tm, err := cs.Exists(SetContext(nil, nil, req), "uid")
	assert.Error(t, err)
	assert.False(t, v)
	assert.Equal(t, time.Time{}, tm)

	// Write token to cookie
	rec := NewResponseRecorder()
	ctx := SetContext(nil, rec, nil)
	err = cs.Store(ctx, "token", "uid", time.Hour)
	assert.NoError(t, err)
	assert.NotNil(t, rec.Header().Get("Set-Cookie"))

	// Read response
	resp := rec.Response()
	req, err = http.NewRequest("", "", nil)
	assert.NoError(t, err)
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}

	// Check Exists
	v, tm, err = cs.Exists(SetContext(nil, nil, req), "uid")
	assert.NoError(t, err)
	assert.True(t, v)
	assert.NotEqual(t, time.Time{}, tm)

	// Check Exists fails for wrong uid
	v, tm, err = cs.Exists(SetContext(nil, nil, req), "anotheruid")
	assert.Equal(t, err, ErrWrongTokenUID)
	assert.False(t, v)
	assert.Equal(t, time.Time{}, tm)

	// Test bad cookie fails verification
	req, err = http.NewRequest("", "", nil)
	req.AddCookie(&http.Cookie{Name: "passwordless", Value: "invalid!"})
	v, tm, err = cs.Exists(SetContext(nil, nil, req), "uid")
	assert.Error(t, err)
	assert.False(t, v)
	assert.Equal(t, time.Time{}, tm)
}

func TestSessionStoreVerify(t *testing.T) {
	cs := NewCookieStore([]byte(""), []byte(""), []byte("testtesttesttest"))

	// Write token to cookie
	rec := NewResponseRecorder()
	ctx := SetContext(nil, rec, nil)
	err := cs.Store(ctx, "token", "uid", time.Hour)
	assert.NoError(t, err)
	assert.NotNil(t, rec.Header().Get("Set-Cookie"))

	// Read response
	resp := rec.Response()
	req, err := http.NewRequest("", "", nil)
	assert.NoError(t, err)
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}

	// Verify bad token fails
	v, err := cs.Verify(SetContext(nil, nil, req), "badtoken", "uid")
	assert.NoError(t, err)
	assert.False(t, v)

	// Verify good token succeeds
	v, err = cs.Verify(SetContext(nil, nil, req), "token", "uid")
	assert.NoError(t, err)
	assert.True(t, v)
}

func TestSessionStoreDelete(t *testing.T) {
	cs := NewCookieStore([]byte(""), []byte(""), []byte(""))
	err := cs.Delete(nil, "")
	assert.Equal(t, ErrNoResponseWriter, err)

	rec := NewResponseRecorder()
	err = cs.Delete(SetContext(nil, rec, nil), "")
	assert.Nil(t, err)
	assert.NotEmpty(t, rec.Header().Get("Set-Cookie"))
}

type ResponseRecorder struct {
	*httptest.ResponseRecorder
}

func NewResponseRecorder() *ResponseRecorder {
	return &ResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
	}
}

func (r ResponseRecorder) Response() *http.Response {
	return &http.Response{
		StatusCode: r.Code,
		Header:     r.HeaderMap,
		Body:       ioutil.NopCloser(r.Body),
	}
}
