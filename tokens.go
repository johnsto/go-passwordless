package passwordless

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/net/context"
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
	c := len(g.Bytes)
	b := make([]byte, g.Length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	j := 0
	for i := 0; i < g.Length; i++ {
		bb := int(b[i])
		b[i] = g.Bytes[(j+bb)%c]
		j += (c + (c-bb)%c) % c
	}
	return string(b), nil
}

func (g ByteGenerator) Sanitize(ctx context.Context, s string) (string, error) {
	return s, nil
}

// CrockfordGenerator generates random tokens using Douglas Crockford's base
// 32 alphabet which limits characters of similar appearances. The
// Sanitize method of this generator will deal with transcribing incorrect
// characters back to the correct value.
type CrockfordGenerator struct {
	*ByteGenerator
}

// NewCrockfordGenerator returns a new Crockford token generator that creates
// tokens of the specified length.
func NewCrockfordGenerator(l int) *CrockfordGenerator {
	return &CrockfordGenerator{
		ByteGenerator: NewByteGenerator([]byte("0123456789abcdefghjkmnpqrstvwxyz"), l),
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
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	} else {
		max := int(math.Pow10(g.Length))
		i := int(big.NewInt(0).SetBytes(b).Int64())
		r := (i%max + max) % max
		return fmt.Sprintf("%0"+strconv.Itoa(g.Length)+"d", r), nil
	}
}

func (g PINGenerator) Sanitize(ctx context.Context, s string) (string, error) {
	return s, nil
}
