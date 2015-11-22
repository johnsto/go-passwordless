package passwordless

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

type testTransport struct {
	token     string
	recipient string
	err       error
}

func (t *testTransport) Send(ctx context.Context, token, recipient string) error {
	t.token = token
	t.recipient = recipient
	return t.err
}

type testGenerator struct {
	token string
	err   error
}

func (g testGenerator) Generate(ctx context.Context) (string, error) {
	return g.token, g.err
}

func (g testGenerator) Sanitize(ctx context.Context, s string) (string, error) {
	return s, nil
}

func TestPasswordless(t *testing.T) {
	p := New(NewMemStore())
	tt := &testTransport{}
	tg := &testGenerator{token: "1337"}
	p.SetTransport("test", tt, tg, 5*time.Minute)

	// Check transports match those set
	assert.Equal(t, map[string]Transport{"test": tt}, p.ListTransports(nil))
	assert.Equal(t, tt, p.GetTransport(nil, "test"))

	// Check returned token is as expected
	assert.NoError(t, p.RequestToken(nil, "test", "uid", "recipient"))
	assert.Equal(t, tt.token, tg.token)
	assert.Equal(t, tt.recipient, "recipient")

	// Check invalid token is rejected
	v, err := p.VerifyToken(nil, "uid", "badtoken")
	assert.Error(t, err)
	assert.False(t, v)

	// Verify token
	v, err = p.VerifyToken(nil, "uid", tg.token)
	assert.NoError(t, err)
	assert.True(t, v)
}
