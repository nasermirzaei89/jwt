package jwt

import (
	"fmt"
)

// Algorithm interface.
type Algorithm interface {
	fmt.Stringer
	Sign(key []byte, unsignedToken string) (string, error)
	Verify(key []byte, unsignedToken, signature string) error
}
