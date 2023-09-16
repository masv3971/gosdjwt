package gosdjwt

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
)

// Client is a SD-JWT client
type Client struct {
	config Config
}

// Config holds the configuration for the SD-JWT
type Config struct {
	JWTType       string
	SigningMethod jwt.SigningMethod
}

// New creates a new SD-JWT client
func New(ctx context.Context, config Config) (*Client, error) {
	client := &Client{
		config: config,
	}

	return client, nil
}
