package passwordless

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestByteGenerator(t *testing.T) {
	bg := ByteGenerator{Bytes: []byte("a"), Length: 1}
	s, err := bg.Generate(nil)
	assert.NoError(t, err)
	assert.Equal(t, "a", s)

	bg.Bytes = []byte("b")
	s, err = bg.Generate(nil)
	assert.NoError(t, err)
	assert.Equal(t, "b", s)

	bg.Length = 2
	s, err = bg.Generate(nil)
	assert.NoError(t, err)
	assert.Equal(t, "bb", s)

	d := map[string]int{"aa": 0, "ab": 0, "ba": 0, "bb": 0}
	bg.Bytes = []byte("ab")
	for len(d) > 0 {
		s, err = bg.Generate(nil)
		assert.NoError(t, err)
		delete(d, s)
	}
}

func TestPINGenerator(t *testing.T) {
	// Simple check for length
	for _, v := range []int{1, 2, 3, 4, 5} {
		ng := PINGenerator{Length: v}
		s, err := ng.Generate(nil)
		assert.NoError(t, err)
		assert.Len(t, s, v)
	}

	// Check sanitizer
	ng := PINGenerator{}
	s, err := ng.Sanitize(nil, "1iIlL2345sS6b78B90oO")
	assert.NoError(t, err)
	assert.Equal(t, "11111234555667889000", s)

}

func TestCrockfordGenerator(t *testing.T) {
	// Simple check for length
	for _, v := range []int{1, 2, 3, 4, 5} {
		ng := CrockfordGenerator{Length: v}
		s, err := ng.Generate(nil)
		assert.NoError(t, err)
		assert.Len(t, s, v)
	}

	// Check sanitizer
	ng := CrockfordGenerator{}
	s, err := ng.Sanitize(nil, "abcdefghijklmnopqrstuvwxyz"+
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789|")
	assert.NoError(t, err)
	assert.Equal(t, "abcdefgh1jk1mn0pqrstuvwxyz"+
		"abcdefgh1jk1mn0pqrstuvwxyz01234567891", s)

}

func TestRandBytes(t *testing.T) {
	b, err := randBytes(make([]byte, 500), 5)
	assert.Nil(t, b)
	assert.Error(t, err)
}
