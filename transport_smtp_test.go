package passwordless

import (
	"io"
	"testing"

	"golang.org/x/net/context"
)

func TestSMTPTransport(t *testing.T) {
	if false {
		tr := NewSMTPTransport("localhost:1025", "test@example.com", "subject", nil, func(ctx context.Context, token, recipient string, w io.Writer) error {
			return nil
		})
		tr.Send(nil, "token", "recipient@example.com")
	}
}
