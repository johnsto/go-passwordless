package passwordless

import (
	"errors"
	"time"

	"context"
)

var (
	ErrNoStore            = errors.New("no store has been configured")
	ErrNoTransport        = errors.New("no transports have been configured")
	ErrUnknownStrategy    = errors.New("unknown strategy")
	ErrNotValidForContext = errors.New("strategy not valid for context")
)

// Strategy defines how to send and what tokens to send to users.
type Strategy interface {
	Transport
	TokenGenerator
	// TTL should return the time-to-live of generated tokens.
	TTL(context.Context) time.Duration
	// Valid should return true if this strategy is valid for the provided
	// context.
	Valid(context.Context) bool
}

// SimpleStrategy is a convenience wrapper combining a Transport,
// TokenGenerator, and TTL.
type SimpleStrategy struct {
	Transport
	TokenGenerator
	ttl time.Duration
}

// TTL returns the time-to-live of tokens generated with this strategy.
func (s SimpleStrategy) TTL(context.Context) time.Duration {
	return s.ttl
}

// Valid always returns true for SimpleStrategy.
func (s SimpleStrategy) Valid(context.Context) bool {
	return true
}

// Passwordless holds a set of named strategies and an associated token store.
type Passwordless struct {
	Strategies map[string]Strategy
	Store      TokenStore
}

// New returns a new Passwordless instance with the specified token store.
// Register strategies against this instance with either `SetStrategy` or
// `SetTransport`.
func New(store TokenStore) *Passwordless {
	return &Passwordless{
		Store:      store,
		Strategies: make(map[string]Strategy),
	}
}

// SetStrategy registers the given strategy.
func (p *Passwordless) SetStrategy(name string, s Strategy) {
	p.Strategies[name] = s
}

// SetTransport registers a transport strategy under a specified name. The
// TTL specifies for how long tokens generated with the provided TokenGenerator
// are valid. Some delivery mechanisms may require longer TTLs than others
// depending on the nature/punctuality of the transport.
func (p *Passwordless) SetTransport(name string, t Transport, g TokenGenerator, ttl time.Duration) Strategy {
	s := SimpleStrategy{
		Transport:      t,
		TokenGenerator: g,
		ttl:            ttl,
	}
	p.SetStrategy(name, s)
	return s
}

// ListStrategies returns a list of strategies valid for the context mapped
// to their names. If you have multiple strategies, call this in order to
// provide a list of options for the user to pick from.
func (p *Passwordless) ListStrategies(ctx context.Context) map[string]Strategy {
	s := map[string]Strategy{}
	for n, t := range p.Strategies {
		if t.Valid(ctx) {
			s[n] = t
		}
	}
	return s
}

// GetStrategy returns the Strategy of the given name, or nil if one does
// not exist.
func (p *Passwordless) GetStrategy(ctx context.Context, name string) (Strategy, error) {
	t, ok := p.Strategies[name]
	if !ok {
		return nil, ErrUnknownStrategy
	} else if !t.Valid(ctx) {
		return nil, ErrNotValidForContext
	}
	return t, nil
}

// RequestToken generates and delivers a token to the given user. If the
// specified strategy is not known or not valid, an error is returned.
func (p *Passwordless) RequestToken(ctx context.Context, s, uid, recipient string) error {
	if t, err := p.GetStrategy(ctx, s); err != nil {
		return err
	} else {
		return RequestToken(ctx, p.Store, t, uid, recipient)
	}
}

// PostVerifyAction is an action to take after validation has succesfully occured.
type PostVerifyAction func(ctx context.Context, s TokenStore, uid, token string, valid bool) (bool, error)

// WithValidDelete when a token is a valid, this deletes it from the store.
func WithValidDelete() PostVerifyAction {
	return func(ctx context.Context, s TokenStore, uid, _ string, valid bool) (bool, error) {
		if valid {
			return valid, s.Delete(ctx, uid)
		}
		return valid, nil
	}
}

// VerifyToken verifies the provided token is valid.
func (p *Passwordless) VerifyToken(ctx context.Context, uid, token string) (bool, error) {
	return VerifyToken(ctx, p.Store, uid, token)
}

func (p *Passwordless) VerifyTokenWithOptions(ctx context.Context, uid, token string, actions ...PostVerifyAction) (bool, error) {
	return VerifyTokenWithOptions(ctx, p.Store, uid, token, actions...)
}

// RequestToken generates, saves and delivers a token to the specified
// recipient.
func RequestToken(ctx context.Context, s TokenStore, t Strategy, uid, recipient string) error {
	tok, err := t.Generate(ctx)
	if err != nil {
		return err
	}
	// Store token
	if err := s.Store(ctx, tok, uid, t.TTL(ctx)); err != nil {
		return err
	}
	// Send token to user
	if err := t.Send(ctx, tok, uid, recipient); err != nil {
		return err
	}
	return nil
}

// VerifyToken checks the given token against the provided token store, on successful
// validation it deletes the token.
func VerifyToken(ctx context.Context, s TokenStore, uid, token string) (bool, error) {
	return VerifyTokenWithOptions(ctx, s, uid, token, WithValidDelete())
}

// VerifyTokenWithOptions
func VerifyTokenWithOptions(ctx context.Context, s TokenStore, uid, token string, actions ...PostVerifyAction) (bool, error) {
	isValid, err := s.Verify(ctx, token, uid)
	if err != nil {
		// Failed to validate
		return false, err
	}
	for _, action := range actions {
		isValid, err = action(ctx, s, uid, token, isValid)
		if err != nil {
			return isValid, err
		}
	}
	return isValid, nil
}
