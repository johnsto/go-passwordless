package appengine

import (
	"context"
	"google.golang.org/appengine/mail"
)

// MailTransport sends token messages via the mail service.
type MailTransport struct {
	// MessageFunc should return a `mail.Message` for the given recipient and
	// token.
	MessageFunc func(ctx context.Context, token, user, recipient string) (*mail.Message, error)
}

// Send sends an XMPP message to the specified recipient.
func (t MailTransport) Send(ctx context.Context, token, user, recipient string) error {
	if msg, err := t.MessageFunc(ctx, token, user, recipient); err != nil {
		return nil
	} else {
		return mail.Send(ctx, msg)
	}
}
