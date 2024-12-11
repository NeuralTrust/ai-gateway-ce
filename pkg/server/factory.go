package server

import (
	"github.com/sirupsen/logrus"
)

// New creates a new server instance with default configuration
func New() *BaseServer {
	logger := logrus.New()
	config := NewConfig() // Use NewConfig instead of &Config{}

	return NewBaseServer(config, nil, nil, logger)
}
