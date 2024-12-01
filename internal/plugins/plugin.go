package plugins

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
)

// RequestContext contains all the information about the request
type RequestContext struct {
	TenantID        string
	OriginalRequest *http.Request
	ForwardRequest  *http.Request
	Rule            interface{}
	Metadata        map[string]interface{}
	RequestBody     map[string]interface{} // Parsed JSON body
	SelectedFields  []string               // Fields to include in forward request
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

type ExecutionStage int

const (
	PreRequest ExecutionStage = iota
	PostRequest
	PreResponse
	PostResponse
)

// Plugin represents a middleware plugin that can process requests
type Plugin interface {
	Name() string
	Priority() int
	Stage() ExecutionStage
	Parallel() bool
	ProcessRequest(ctx context.Context, reqCtx *RequestContext) error
	ProcessResponse(ctx context.Context, respCtx *ResponseContext) error
}

// Registry manages the available plugins
type Registry struct {
	plugins map[string]Plugin
	mu      sync.RWMutex
}

func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
	}
}

// Register adds a plugin to the registry
func (r *Registry) Register(p Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.plugins[p.Name()]; exists {
		return fmt.Errorf("plugin %s already registered", p.Name())
	}
	r.plugins[p.Name()] = p
	return nil
}

// Get returns a plugin by name
func (r *Registry) Get(name string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.plugins[name]
	return p, ok
}

// ExecutePlugins executes plugins for a given stage
func (r *Registry) ExecutePlugins(ctx context.Context, stage ExecutionStage, req *http.Request, resp *http.Response) error {
	plugins := r.getPluginsForStage(stage)
	if len(plugins) == 0 {
		return nil
	}

	// Group plugins by parallel capability
	var serialPlugins, parallelPlugins []Plugin
	for _, p := range plugins {
		if p.Parallel() {
			parallelPlugins = append(parallelPlugins, p)
		} else {
			serialPlugins = append(serialPlugins, p)
		}
	}

	// Execute parallel plugins
	if len(parallelPlugins) > 0 {
		errChan := make(chan error, len(parallelPlugins))
		var wg sync.WaitGroup

		for _, p := range parallelPlugins {
			wg.Add(1)
			go func(plugin Plugin) {
				defer wg.Done()
				var err error
				if resp == nil {
					err = plugin.ProcessRequest(ctx, req)
				} else {
					err = plugin.ProcessResponse(ctx, resp)
				}
				if err != nil {
					errChan <- fmt.Errorf("plugin %s failed: %w", plugin.Name(), err)
				}
			}(p)
		}

		// Wait for all parallel plugins to complete
		wg.Wait()
		close(errChan)

		// Check for errors
		for err := range errChan {
			if err != nil {
				return err
			}
		}
	}

	// Execute serial plugins
	for _, p := range serialPlugins {
		var err error
		if resp == nil {
			err = p.ProcessRequest(ctx, req)
		} else {
			err = p.ProcessResponse(ctx, resp)
		}
		if err != nil {
			return fmt.Errorf("plugin %s failed: %w", p.Name(), err)
		}
	}

	return nil
}

func (r *Registry) getPluginsForStage(stage ExecutionStage) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var stagePlugins []Plugin
	for _, p := range r.plugins {
		if p.Stage() == stage {
			stagePlugins = append(stagePlugins, p)
		}
	}

	// Sort plugins by priority
	sort.Slice(stagePlugins, func(i, j int) bool {
		return stagePlugins[i].Priority() < stagePlugins[j].Priority()
	})

	return stagePlugins
}
