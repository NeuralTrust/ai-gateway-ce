package server

import (
	"sync"

	"github.com/valyala/fasthttp"
)

type RequestPipeline struct {
	workers    int
	batchSize  int
	requests   chan *fasthttp.Request
	responses  chan *fasthttp.Response
	client     *fasthttp.Client
	bufferPool *sync.Pool
}

func NewRequestPipeline(workers, batchSize int) *RequestPipeline {
	return &RequestPipeline{
		workers:    workers,
		batchSize:  batchSize,
		requests:   make(chan *fasthttp.Request, batchSize*2),
		responses:  make(chan *fasthttp.Response, batchSize*2),
		client:     fastClient,
		bufferPool: &bufferPool,
	}
}

func (p *RequestPipeline) Start() {
	for i := 0; i < p.workers; i++ {
		go p.worker()
	}
}

func (p *RequestPipeline) worker() {
	for req := range p.requests {
		resp := fasthttp.AcquireResponse()
		if err := p.client.Do(req, resp); err != nil {
			fasthttp.ReleaseResponse(resp)
			continue
		}
		p.responses <- resp
	}
}

func (p *RequestPipeline) Submit(req *fasthttp.Request) *fasthttp.Response {
	p.requests <- req
	return <-p.responses
}

func (p *RequestPipeline) Stop() {
	close(p.requests)
	close(p.responses)
}
