package server

import (
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

var (
	// FastHTTP client for better performance
	fastClient = &fasthttp.Client{
		MaxConnsPerHost: 10000,
		ReadTimeout:     10 * time.Second,
		WriteTimeout:    10 * time.Second,
	}

	// Buffer pool for response bodies
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}
)
