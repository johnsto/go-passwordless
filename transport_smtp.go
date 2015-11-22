package passwordless

import (
	"crypto/tls"
	"io"
	"net"
	"net/smtp"

	"golang.org/x/net/context"
)

// ComposerFunc is called when writing the contents of an email, including
// preamble headers.
type ComposerFunc func(ctx context.Context, token, recipient string, w io.Writer) error

// SMTPTransport delivers a user token via e-mail.
type SMTPTransport struct {
	UseSSL   bool
	auth     smtp.Auth
	from     string
	addr     string
	subject  string
	composer ComposerFunc
}

// NewSMTPTransport returns a new transport capable of sending emails via
// SMTP. `addr` should be in the form "host:port" of the email server.
func NewSMTPTransport(addr, from, subject string, auth smtp.Auth, c ComposerFunc) *SMTPTransport {
	return &SMTPTransport{
		UseSSL:   false,
		addr:     addr,
		auth:     auth,
		from:     from,
		subject:  subject,
		composer: c,
	}
}

// Send sends an email to the email address specified in `recipient`,
// containing the user token provided.
func (t *SMTPTransport) Send(ctx context.Context, token, recipient string) error {
	host, _, _ := net.SplitHostPort(t.addr)

	// If UseSSL is true, need to ensure the connection is made over a
	// TLS channel.
	var c *smtp.Client
	if t.UseSSL {
		// Connect with SSL handshake
		tlscfg := &tls.Config{
			ServerName: host,
		}
		if conn, err := tls.Dial("tcp", t.addr, tlscfg); err != nil {
			return err
		} else if c, err = smtp.NewClient(conn, host); err != nil {
			defer c.Close()
			defer conn.Close()
			return err
		}
	} else {
		// Not using SSL handshake
		if cl, err := smtp.Dial(t.addr); err != nil {
			return err
		} else {
			defer c.Close()
			c = cl
		}
	}

	// Use STARTTLS if available
	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: host}
		if err := c.StartTLS(config); err != nil {
			return err
		}
	}

	// Use auth credentials if supported and provided
	if ok, _ := c.Extension("AUTH"); ok && t.auth != nil {
		if err := c.Auth(t.auth); err != nil {
			return err
		}
	}

	// Compose email
	if err := c.Mail(t.from); err != nil {
		return err
	}
	if err := c.Rcpt(recipient); err != nil {
		return err
	}

	// Write body
	w, err := c.Data()
	if err != nil {
		return err
	}

	// Emit message body
	if err := t.composer(ctx, token, recipient, w); err != nil {
		return err
	}

	// Close writer
	if err := w.Close(); err != nil {
		return err
	}

	// Succeeded; quit nicely
	return c.Quit()
}
