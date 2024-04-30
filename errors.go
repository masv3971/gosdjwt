package gosdjwt

import (
	"errors"
)

var (
	// ErrTokenNotValid is returned when the JWT token is not valid
	ErrTokenNotValid = errors.New("token is not valid")

	// ErrBase64EncodedEmpty is returned when the base64 encoded string is empty in Instruction
	ErrBase64EncodedEmpty = errors.New("base64Encoded is empty")
)
