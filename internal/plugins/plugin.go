package plugins

import (
	"context"
	"net/http"
)

type Plugin interface {
	Name() string
	Priority() int
	Stage() ExecutionStage
	Parallel() bool
	ProcessRequest(ctx context.Context, reqCtx *RequestContext) error
	ProcessResponse(ctx context.Context, respCtx *ResponseContext) error
}

type ExecutionStage int

const (
	PreRequest ExecutionStage = iota
	PostRequest
	PreResponse
	PostResponse
)

// RequestContext contains all the information about the request
type RequestContext struct {
	TenantID        string
	OriginalRequest *http.Request
	ForwardRequest  *http.Request
	Rule            interface{}
	Metadata        map[string]interface{}
	RequestBody     map[string]interface{}
	SelectedFields  []string
}

// ResponseContext contains all the information about the response
type ResponseContext struct {
	TenantID        string
	OriginalRequest *http.Request
	Response        *http.Response
	Metadata        map[string]interface{}
	ResponseBody    map[string]interface{}
	SelectedFields  []string
}
