package server

import (
	"github.com/valyala/fasthttp"
)

// Pre-encoded responses
var (
	pingResponse     = []byte(`{"message":"pong"}`)
	healthResponse   = []byte(`{"status":"ok"}`)
	notFoundResponse = []byte(`{"error":"not found"}`)
)

func (s *ProxyServer) handleFastPing(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")
	ctx.Write(pingResponse)
}

func (s *ProxyServer) handleFastHealth(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")
	ctx.Write(healthResponse)
}

func (s *ProxyServer) handleFastForward(ctx *fasthttp.RequestCtx) {
	// Get request from pool
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Copy original request
	ctx.Request.CopyTo(req)

	// Forward request
	err := fastClient.Do(req, resp)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}

	// Copy response headers
	resp.Header.VisitAll(func(k, v []byte) {
		ctx.Response.Header.Set(string(k), string(v))
	})

	// Set status code
	ctx.SetStatusCode(resp.StatusCode())

	// Write body
	ctx.Write(resp.Body())
}
