package passwordless

import (
	"crypto/rand"
	"errors"
	"strings"

	"golang.org/x/net/context"
)

var (
	crockfordBytes = []byte("0123456789abcdefghjkmnpqrstvwxyz")
)

// TokenGenerator defines an interface for generating and sanitising
// cryptographically-secure tokens.
type TokenGenerator interface {
	// Generate should return a token and nil error on success, or an empty
	// string and error on failure.
	Generate(ctx context.Context) (string, error)

	// Sanitize should take a user provided input and sanitize it such that
	// it can be passed to a function that expects the same input as
	// `Generate()`. Useful for cases where the token may be subject to
	// minor transcription errors by a user. (e.g. 0 == O)
	Sanitize(ctx context.Context, s string) (string, error)
}

// ByteGenerator generates random sequences of bytes from the specified set
// of the specified length.
type ByteGenerator struct {
	Bytes  []byte
	Length int
}

// NewByteGenerator creates and returns a ByteGenerator.
func NewByteGenerator(b []byte, l int) *ByteGenerator {
	return &ByteGenerator{
		Bytes:  b,
		Length: l,
	}
}

// Generate returns a string generated from random bytes of the configured
// set, of the given length. An error may be returned if there is insufficient
// entropy to generate a result.
func (g ByteGenerator) Generate(ctx context.Context) (string, error) {
	if b, err := randBytes(g.Bytes, g.Length); err != nil {
		return "", err
	} else {
		return string(b), nil
	}
}

func (g ByteGenerator) Sanitize(ctx context.Context, s string) (string, error) {
	return s, nil
}

// CrockfordGenerator generates random tokens using Douglas Crockford's base
// 32 alphabet which limits characters of similar appearances. The
// Sanitize method of this generator will deal with transcribing incorrect
// characters back to the correct value.
type CrockfordGenerator struct {
	Length int
}

// NewCrockfordGenerator returns a new Crockford token generator that creates
// tokens of the specified length.
func NewCrockfordGenerator(l int) *CrockfordGenerator {
	return &CrockfordGenerator{l}
}

func (g CrockfordGenerator) Generate(ctx context.Context) (string, error) {
	if b, err := randBytes(crockfordBytes, g.Length); err != nil {
		return "", err
	} else {
		return string(b), nil
	}
}

// Sanitize attempts to translate strings back to the correct Crockford
// alphabet, in case of user transcribe errors.
func (g CrockfordGenerator) Sanitize(ctx context.Context, s string) (string, error) {
	bs := []byte(strings.ToLower(s))
	for i, b := range bs {
		if b == 'i' || b == 'l' || b == '|' {
			bs[i] = '1'
		} else if b == 'o' {
			bs[i] = '0'
		}
	}
	return string(bs), nil
}

// PINGenerator generates numerical PINs of the specifeid length.
type PINGenerator struct {
	Length int
}

// Generate returns a numerical PIN of the chosen length. If there is not
// enough random entropy, the returned string will be empty and an error
// value present.
func (g PINGenerator) Generate(ctx context.Context) (string, error) {
	if b, err := randBytes([]byte("0123456789"), g.Length); err != nil {
		return "", err
	} else {
		return string(b), nil
	}
}

func (g PINGenerator) Sanitize(ctx context.Context, s string) (string, error) {
	bs := []byte(strings.ToLower(s))
	for i, b := range bs {
		if b == 'i' || b == 'l' || b == '|' {
			bs[i] = '1'
		} else if b == 'o' {
			bs[i] = '0'
		} else if s[i] == 'B' {
			bs[i] = '8'
		} else if s[i] == 'b' {
			bs[i] = '6'
		} else if b == 's' {
			bs[i] = '5'
		}
	}
	return string(bs), nil
}

// randBytes returns a random array of bytes picked from `p` of length `n`.
func randBytes(p []byte, n int) ([]byte, error) {
	if len(p) > 256 {
		return nil, errors.New("randBytes requires a pool of <= 256 items")
	}
	c := len(p)
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	// Pick items randomly out of `p`. Because it's possible that
	// `len(p) < size(byte)`, use remainder in next iteration to ensure all
	// bytes have an equal chance of being selected.
	j := 0 // reservoir
	for i := 0; i < n; i++ {
		bb := int(b[i])
		b[i] = p[(j+bb)%c]
		j += (c + (c-bb)%c) % c
	}
	return b, nil
}
