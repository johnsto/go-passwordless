package passwordless

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/net/context"
)

var (
	ErrNoStore     = errors.New("no store has been configured")
	ErrNoTransport = errors.New("no transports have been configured")
)

type strategy struct {
	t   Transport
	g   TokenGenerator
	ttl time.Duration
}

type Passwordless struct {
	transports map[string]strategy
	store      TokenStore
	opts       Options
}

type Options struct {
}

func New(store TokenStore) *Passwordless {
	return &Passwordless{
		store:      store,
		transports: make(map[string]strategy),
	}
}

// SetTransport registers a transport strategy under a specified name. The
// TTL specifies for how long tokens generated with the provided TokenGenerator
// are valid. Some delivery mechanisms may require longer TTLs than others
// depending on the nature/punctuality of the transport.
func (p *Passwordless) SetTransport(name string, t Transport, g TokenGenerator, ttl time.Duration) {
	p.transports[name] = strategy{
		t:   t,
		g:   g,
		ttl: ttl,
	}
}

// ListTransports returns a list of transports mapped to their respective
// names. When multiple transports are registered, this can be useful if you
// want to let the user choose one.
func (p *Passwordless) ListTransports(ctx context.Context) map[string]Transport {
	ts := map[string]Transport{}
	for n, t := range p.transports {
		ts[n] = t.t
	}
	return ts
}

// GetTransport returns the Transport of the given name, or nil if one does
// not exist.
func (p *Passwordless) GetTransport(ctx context.Context, name string) Transport {
	return p.transports[name].t
}

// RequestToken generates and delivers a token to the given user.
func (p *Passwordless) RequestToken(ctx context.Context, s, uid, recipient string) error {
	st, ok := p.transports[s]
	if !ok {
		return fmt.Errorf("unknown strategy '%s'", s)
	}
	return requestToken(ctx, p.store, st.t, st.g, uid, recipient, st.ttl)
}

// VerifyToken verifies the provided token is valid.
func (p *Passwordless) VerifyToken(ctx context.Context, uid, token string) (bool, error) {
	return verifyToken(ctx, p.store, uid, token)
}

// requestToken generates, saves and delivers a token to the specified
// recipient.
func requestToken(ctx context.Context, s TokenStore, t Transport, g TokenGenerator, uid, recipient string, ttl time.Duration) error {
	tok, err := g.Generate(nil)
	if err != nil {
		return err
	}
	// Store token
	if err := s.Store(ctx, tok, uid, ttl); err != nil {
		return err
	}
	// Send token to use
	if err := t.Send(ctx, tok, uid, recipient); err != nil {
		return err
	}
	return nil
}

// verifyToken checks the given token.
func verifyToken(ctx context.Context, s TokenStore, uid, token string) (bool, error) {
	if isValid, err := s.Verify(ctx, token, uid); err != nil {
		return false, err
	} else if !isValid {
		return false, nil
	}

	// Delete old token
	return true, s.Delete(ctx, uid)
}
