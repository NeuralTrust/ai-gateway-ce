package middleware

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
)

type MetricsMiddleware struct {
	logger *logrus.Logger
}

func NewMetricsMiddleware(logger *logrus.Logger) *MetricsMiddleware {
	return &MetricsMiddleware{
		logger: logger,
	}
}

func (m *MetricsMiddleware) MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		gatewayID := c.GetString(GatewayContextKey)

		// Record connections if enabled
		if metrics.Config.EnableConnections {
			metrics.GatewayConnections.WithLabelValues(gatewayID, "active").Inc()
		}

		c.Next()

		// Always record basic latency
		duration := float64(time.Since(start).Milliseconds())
		metrics.GatewayRequestLatency.WithLabelValues(
			gatewayID,
			"total",
		).Observe(duration)

		// Record detailed metrics if enabled
		if metrics.Config.EnablePerRoute {
			service := c.GetString("service_id")
			route := c.GetString("route_id")
			metrics.GatewayDetailedLatency.WithLabelValues(
				gatewayID,
				service,
				route,
			).Observe(duration)
		}

		// Always record request total
		status := metrics.GetStatusClass(fmt.Sprint(c.Writer.Status()))
		metrics.GatewayRequestTotal.WithLabelValues(
			gatewayID,
			c.Request.Method,
			status,
		).Inc()

		// Decrease connections if enabled
		if metrics.Config.EnableConnections {
			metrics.GatewayConnections.WithLabelValues(gatewayID, "active").Dec()
		}
	}
}
