package passwordless

import (
	"io/ioutil"
	"mime/multipart"
	"net/mail"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEmail(t *testing.T) {
	d := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	e := Email{
		To:      "bender@ilovebender.com",
		Subject: "Mom Calling",
		Date:    d,
	}

	// Empty body
	m, err := mail.ReadMessage(e.Buffer())
	assert.NoError(t, err)
	assert.Equal(t, "bender@ilovebender.com", m.Header.Get("To"))
	assert.Equal(t, "Mom Calling", m.Header.Get("Subject"))
	assert.Equal(t, d.Format(time.RFC822), m.Header.Get("Date"))

	// Plain body
	e.AddBody("", "Hello dear")
	m, err = mail.ReadMessage(e.Buffer())
	assert.NoError(t, err)
	assert.Equal(t, "text/plain; charset=\"UTF-8\";", m.Header.Get("Content-Type"))
	body, err := ioutil.ReadAll(m.Body)
	assert.NoError(t, err)
	assert.Equal(t, "Hello dear\r\n", string(body))

	// Additional HTML body (multipart)
	e.AddBody("text/html", "<html><body>Hello dear</body></html>")
	m, err = mail.ReadMessage(e.Buffer())
	ct := m.Header.Get("Content-Type")
	re := regexp.MustCompile("^multipart/alternative; boundary=([a-z0-9]+)$")
	assert.Regexp(t, re, ct)
	boundary := re.FindStringSubmatch(ct)[1]
	assert.NotEmpty(t, boundary)

	mpr := multipart.NewReader(m.Body, boundary)

	// Read first part
	p, err := mpr.NextPart()
	assert.NoError(t, err, "reading first part")
	assert.Equal(t, "text/plain; charset=\"UTF-8\";", p.Header.Get("Content-Type"))
	body, err = ioutil.ReadAll(p)
	assert.NoError(t, err, "reading body of first part")
	assert.Equal(t, "Hello dear", string(body))

	// Read second part
	p, err = mpr.NextPart()
	assert.NoError(t, err, "reading second part")
	assert.Equal(t, "text/html; charset=\"UTF-8\";", p.Header.Get("Content-Type"))
	body, err = ioutil.ReadAll(p)
	assert.NoError(t, err, "reading body of second part")
	assert.Equal(t, "<html><body>Hello dear</body></html>", string(body))

	// Read (non-existent) next part
	p, err = mpr.NextPart()
	assert.Nil(t, p)
}
