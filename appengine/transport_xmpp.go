package appengine

import (
	"golang.org/x/net/context"
	"google.golang.org/appengine/xmpp"
)

// XMPPTransport sends tokens via the XMPP service.
type XMPPTransport struct {
	MessageFunc func(ctx context.Context, token, user, recipient string) (*xmpp.Message, error)
}

// Send sends an XMPP message to the specified recipient.
func (t XMPPTransport) Send(ctx context.Context, token, user, recipient string) error {
	if msg, err := t.MessageFunc(ctx, token, user, recipient); err != nil {
		return nil
	} else {
		return msg.Send(ctx)
	}
}
