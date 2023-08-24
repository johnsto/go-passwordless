package passwordless

import (
	"fmt"
	"testing"
	"time"

	"context"

	"github.com/stretchr/testify/assert"
)

type testTransport struct {
	token     string
	recipient string
	err       error
}

func (t *testTransport) Send(ctx context.Context, token, user, recipient string) error {
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
	ctx := context.TODO()
	p := New(NewMemStore())

	tt := &testTransport{}
	tg := &testGenerator{token: "1337"}
	s := p.SetTransport("test", tt, tg, 5*time.Minute)

	// Check transports match those set
	assert.Equal(t, map[string]Strategy{"test": s}, p.ListStrategies(ctx))
	if s0, err := p.GetStrategy(ctx, "test"); err != nil {
		assert.NoError(t, err)
	} else {
		assert.Equal(t, s, s0)
	}

	// Check returned token is as expected
	assert.NoError(t, p.RequestToken(ctx, "test", "uid", "recipient"))
	assert.Equal(t, tt.token, tg.token)
	assert.Equal(t, tt.recipient, "recipient")

	// Check invalid token is rejected
	v, err := p.VerifyToken(ctx, "uid", "badtoken")
	assert.NoError(t, err)
	assert.False(t, v)

	// Verify token
	v, err = p.VerifyToken(ctx, "uid", tg.token)
	assert.NoError(t, err)
	assert.True(t, v)
}

type testStrategy struct {
	SimpleStrategy
	valid bool
}

func (s testStrategy) Valid(c context.Context) bool {
	return s.valid
}

func TestPasswordlessFailures(t *testing.T) {
	ctx := context.TODO()
	p := New(NewMemStore())

	_, err := p.GetStrategy(ctx, "madeup")
	assert.Equal(t, err, ErrUnknownStrategy)

	err = p.RequestToken(ctx, "madeup", "", "")
	assert.Equal(t, err, ErrUnknownStrategy)

	p.SetStrategy("unfriendly", testStrategy{valid: false})

	err = p.RequestToken(ctx, "unfriendly", "", "")
	assert.Equal(t, err, ErrNotValidForContext)
}

func TestRequestToken(t *testing.T) {
	ctx := context.TODO()
	// Test Generate()
	assert.EqualError(t, RequestToken(ctx, nil, &mockStrategy{
		generate: func(c context.Context) (string, error) {
			return "", fmt.Errorf("refused generate")
		},
	}, "", ""), "refused generate", "Generate() error should propagate")

	// Test Send()
	assert.EqualError(t, RequestToken(ctx, &mockTokenStore{
		store: func(ctx context.Context, token, uid string, ttl time.Duration) error {
			return nil
		},
	}, &mockStrategy{
		generate: func(c context.Context) (string, error) {
			return "", nil
		},
		send: func(c context.Context, token, user, recipient string) error {
			return fmt.Errorf("refused send")
		},
	}, "", ""), "refused send", "Send() error should propagate")

	// Test Store()
	err := RequestToken(ctx, &mockTokenStore{
		store: func(ctx context.Context, token, uid string, ttl time.Duration) error {
			return fmt.Errorf("refused store")
		},
	}, &mockStrategy{
		generate: func(c context.Context) (string, error) {
			return "", nil
		},
		send: func(c context.Context, token, user, recipient string) error {
			return nil
		},
	}, "", "")
	assert.EqualError(t, err, "refused store", "Store() error should propagate")
}

func TestVerifyToken(t *testing.T) {
	ctx := context.TODO()
	valid, err := VerifyToken(ctx, &mockTokenStore{
		verify: func(ctx context.Context, token, uid string) (bool, error) {
			return false, fmt.Errorf("refused verify")
		},
	}, "", "")
	assert.False(t, valid)
	assert.EqualError(t, err, "refused verify", "Verify() error should propagate")

	valid, err = VerifyToken(ctx, &mockTokenStore{
		verify: func(ctx context.Context, token, uid string) (bool, error) {
			return false, nil
		},
	}, "", "")
	assert.False(t, valid)
	assert.NoError(t, err)

	valid, err = VerifyToken(ctx, &mockTokenStore{
		verify: func(ctx context.Context, token, uid string) (bool, error) {
			return true, nil
		},
		delete: func(ctx context.Context, uid string) error {
			return fmt.Errorf("delete failure")
		},
	}, "", "")
	assert.True(t, valid)
	assert.EqualError(t, err, "delete failure")
}

func TestVerifyTokenWithOptions(t *testing.T) {
	ctx := context.TODO()
	valid, err := VerifyTokenWithOptions(ctx, &mockTokenStore{
		verify: func(ctx context.Context, token, uid string) (bool, error) {
			return false, fmt.Errorf("refused verify")
		},
	}, "", "")
	assert.False(t, valid)
	assert.EqualError(t, err, "refused verify", "Verify() error should propagate")

	valid, err = VerifyTokenWithOptions(ctx, &mockTokenStore{
		verify: func(ctx context.Context, token, uid string) (bool, error) {
			return false, nil
		},
	}, "", "")
	assert.False(t, valid)
	assert.NoError(t, err)

	valid, err = VerifyTokenWithOptions(ctx, &mockTokenStore{
		verify: func(ctx context.Context, token, uid string) (bool, error) {
			return true, nil
		},
		delete: func(ctx context.Context, uid string) error {
			return fmt.Errorf("delete failure")
		},
	}, "", "")
	assert.True(t, valid)
	assert.NoError(t, err)

	valid, err = VerifyTokenWithOptions(ctx, &mockTokenStore{
		verify: func(ctx context.Context, token, uid string) (bool, error) {
			return true, nil
		},
		delete: func(ctx context.Context, uid string) error {
			return fmt.Errorf("delete failure")
		},
	}, "", "", WithValidDelete())
	assert.True(t, valid)
	assert.EqualError(t, err, "delete failure")
}

type mockStrategy struct {
	SimpleStrategy
	generate func(context.Context) (string, error)
	sanitize func(context.Context, string) (string, error)
	send     func(c context.Context, token, user, recipient string) error
}

func (m mockStrategy) TTL(ctx context.Context) time.Duration {
	return m.ttl
}

func (m mockStrategy) Generate(ctx context.Context) (string, error) {
	return m.generate(ctx)
}

func (m mockStrategy) Sanitize(ctx context.Context, t string) (string, error) {
	return m.sanitize(ctx, t)
}

func (m mockStrategy) Send(ctx context.Context, token, user, recipient string) error {
	return m.send(ctx, token, user, recipient)
}

type mockTokenStore struct {
	store  func(ctx context.Context, token, uid string, ttl time.Duration) error
	exists func(ctx context.Context, uid string) (bool, time.Time, error)
	verify func(ctx context.Context, token, uid string) (bool, error)
	delete func(ctx context.Context, uid string) error
}

func (m mockTokenStore) Store(ctx context.Context, token, uid string, ttl time.Duration) error {
	return m.store(ctx, token, uid, ttl)
}

func (m mockTokenStore) Exists(ctx context.Context, uid string) (bool, time.Time, error) {
	return m.exists(ctx, uid)
}

func (m mockTokenStore) Verify(ctx context.Context, token, uid string) (bool, error) {
	return m.verify(ctx, token, uid)
}

func (m mockTokenStore) Delete(ctx context.Context, uid string) error {
	return m.delete(ctx, uid)
}
