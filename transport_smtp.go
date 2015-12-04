package passwordless

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"time"

	"golang.org/x/net/context"
)

// ComposerFunc is called when writing the contents of an email, including
// preamble headers.
type ComposerFunc func(ctx context.Context, token, user, recipient string, w io.Writer) error

// Email is a helper for creating multipart (text and html) emails
type Email struct {
	Body    []struct{ t, c string }
	To      string
	Subject string
}

// AddBody adds a content section to the email. The `contentType` should
// be a known type, such as "text/html" or "text/plain". If no `contentType`
// is provided, "text/plain" is used. Call this method for each required
// body, with the most preferable type last.
func (e *Email) AddBody(contentType, body string) {
	if e.Body == nil {
		e.Body = make([]struct{ t, c string }, 0)
	}
	if contentType == "" {
		contentType = "text/plain"
	}
	e.Body = append(e.Body, struct{ t, c string }{contentType, body})
}

// Write emits the Email to the specified writer.
func (e Email) Write(w io.Writer) (int64, error) {
	return e.Buffer().WriteTo(w)
}

// Bytes returns the contents of the email as a series of bytes.
func (e Email) Bytes() []byte {
	return e.Buffer().Bytes()
}

func (e Email) Buffer() *bytes.Buffer {
	crlf := "\r\n"
	b := bytes.NewBuffer(nil)

	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC822) + crlf)
	if e.Subject != "" {
		b.WriteString("Subject: " + e.Subject + crlf)
	}
	if e.To != "" {
		b.WriteString("To: " + e.To + crlf)
	}

	boundary := ""
	if len(e.Body) > 1 {
		// Generate boundary to separate sections
		h := md5.New()
		io.WriteString(h, fmt.Sprintf("%s", time.Now().UnixNano()))
		boundary = fmt.Sprintf("%x", h.Sum(nil))

		// Write boundary
		b.WriteString("MIME-version: 1.0" + crlf)
		b.WriteString("Content-Type: multipart/alternative; boundary=" +
			boundary + crlf + crlf)
	}

	for _, body := range e.Body {
		if boundary != "" {
			b.WriteString(crlf + "--" + boundary + crlf)
		}
		b.WriteString("Content-Type: " + body.t + "; charset=\"UTF-8\";")
		b.WriteString(crlf + crlf + body.c + crlf)
	}
	if boundary != "" {
		b.WriteString(crlf + "--" + boundary + "--" + crlf)
	}

	return b
}

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
func (t *SMTPTransport) Send(ctx context.Context, token, uid, recipient string) error {
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
	if err := t.composer(ctx, token, uid, recipient, w); err != nil {
		return err
	}

	// Close writer
	if err := w.Close(); err != nil {
		return err
	}

	// Succeeded; quit nicely
	return c.Quit()
}
