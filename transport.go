package passwordless

import (
	"log"

	"golang.org/x/net/context"
)

// Transport represents a mechanism that sends a named recipient a token.
type Transport interface {
	// Send instructs the transport to send the given token for the specified
	// user to the given recipient, which could be an email address, phone
	// number, or something else.
	Send(ctx context.Context, token, user, recipient string) error
}

// LogTransport is intended for testing/debugging purposes that simply logs
// the token to the console.
type LogTransport struct {
	MessageFunc func(token, uid string) string
}

func (lt LogTransport) Send(ctx context.Context, token, user, recipient string) error {
	log.Printf(lt.MessageFunc(token, user))
	return nil
}
