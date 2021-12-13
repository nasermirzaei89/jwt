package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

var _ Algorithm = HS256{}

type HS256 struct{}

func (alg HS256) Sign(key []byte, unsignedToken string) (string, error) {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(unsignedToken))

	return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
}

func (alg HS256) Verify(key []byte, unsignedToken, signature string) error {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(unsignedToken))

	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid token signature encoding: %w", err)
	}

	if !hmac.Equal(mac.Sum(nil), sig) {
		return ErrInvalidTokenSignature
	}

	return nil
}

func (alg HS256) String() string {
	return "HS256"
}
