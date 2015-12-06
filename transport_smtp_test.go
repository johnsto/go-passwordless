package passwordless

import (
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSMTPTransport(t *testing.T) {
}

func TestEmail(t *testing.T) {
	e := Email{
		To:      "bender@ilovebender.com",
		Subject: "Your Destroy all Humans subscription",
		Date:    time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC),
	}
	exp := "Date: 03 Feb 01 04:05 UTC\r\n" +
		"Subject: Your Destroy all Humans subscription\r\n" +
		"To: bender@ilovebender.com\r\n"
	assert.Equal(t, exp, string(e.Bytes()))

	e.AddBody("", "Has elapsed")
	exp = "Date: 03 Feb 01 04:05 UTC\r\n" +
		"Subject: Your Destroy all Humans subscription\r\n" +
		"To: bender@ilovebender.com\r\n" +
		"Content-Type: text/plain; charset=\"UTF-8\";\r\n" +
		"\r\nHas elapsed\r\n"
	assert.Equal(t, exp, string(e.Bytes()))

	e.AddBody("text/html", "<html>HTML!</html>")
	s := string(e.Bytes())
	r := regexp.MustCompile("boundary=([a-zA-Z0-9]+)\r\n")
	boundary := r.FindStringSubmatch(s)[1]
	exp = "Date: 03 Feb 01 04:05 UTC\r\n" +
		"Subject: Your Destroy all Humans subscription\r\n" +
		"To: bender@ilovebender.com\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=" + boundary + "\r\n" +
		"\r\n" +
		"\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/plain; charset=\"UTF-8\";\r\n" +
		"\r\nHas elapsed\r\n" +
		"\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\";\r\n" +
		"\r\n<html>HTML!</html>\r\n\r\n" +
		"--" + boundary + "--\r\n"
	assert.Equal(t, exp, string(s))
}
