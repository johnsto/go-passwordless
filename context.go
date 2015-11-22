package passwordless

import (
	"net/http"

	"golang.org/x/net/context"
)

type ctxKey int

const (
	reqKey ctxKey = 1
	rwKey  ctxKey = 2
)

func SetContext(ctx context.Context, rw http.ResponseWriter, r *http.Request) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, reqKey, r)
	ctx = context.WithValue(ctx, rwKey, rw)
	return ctx
}

func fromContext(ctx context.Context) (http.ResponseWriter, *http.Request) {
	rw := ctx.Value(rwKey).(http.ResponseWriter)
	r := ctx.Value(reqKey).(*http.Request)
	return rw, r
}
