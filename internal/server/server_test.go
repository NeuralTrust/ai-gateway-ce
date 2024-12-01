package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"ai-gateway/internal/cache"
	"ai-gateway/internal/plugins"
)

func setupTestServer() *Server {
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Create a mock cache for testing
	mockCache, _ := cache.NewCache(cache.Config{
		Host: "localhost",
		Port: 6379,
	})

	// Create plugin registry
	pluginRegistry := plugins.NewRegistry()

	config := &Config{
		Port:       8080,
		BaseDomain: "example.com",
	}

	return NewServer(config, mockCache, logger, pluginRegistry)
}

func TestHealthCheck(t *testing.T) {
	server := setupTestServer()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	server.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "healthy")
}

func TestForwardingRulesEndpoints(t *testing.T) {
	server := setupTestServer()

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		host           string
	}{
		{
			name:           "Get forwarding rules with valid tenant",
			method:         "GET",
			path:           "/api/v1/forwarding-rules",
			expectedStatus: 200,
			host:           "tenant1.example.com",
		},
		{
			name:           "Get forwarding rules with invalid tenant",
			method:         "GET",
			path:           "/api/v1/forwarding-rules",
			expectedStatus: 400,
			host:           "invalid@.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, tt.path, nil)
			req.Host = tt.host
			server.router.ServeHTTP(w, req)
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}
