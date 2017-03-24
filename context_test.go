package passwordless

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"context"
)

type ctxTestKey int

const (
	testKey ctxTestKey = -1
)

func TestContext(t *testing.T) {
	assert.NotNil(t, SetContext(nil, nil, nil))

	ctx := context.Background()
	ctx = context.WithValue(ctx, testKey, "hello")
	rw := httptest.NewRecorder()
	req := &http.Request{}

	ctx = SetContext(ctx, rw, req)

	assert.NotNil(t, ctx)
	rw2, req2 := fromContext(ctx)
	assert.Equal(t, rw, rw2)
	assert.Equal(t, req, req2)
	assert.Equal(t, "hello", ctx.Value(testKey))
}
