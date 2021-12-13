package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

var _ Algorithm = RS256{}

type RS256 struct{}

func (alg RS256) Sign(key []byte, unsignedToken string) (string, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return "", ErrInvalidPem
	}

	private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("error on parse private key: %w", err)
	}

	hashed := sha256.Sum256([]byte(unsignedToken))

	b, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("error on sign token: %w", err)
	}

	return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(b)), nil
}

func (alg RS256) Verify(key []byte, unsignedToken, signature string) error {
	block, _ := pem.Decode(key)
	if block == nil {
		return ErrInvalidPem
	}

	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("error on parse public key: %w", err)
	}

	hashed := sha256.Sum256([]byte(unsignedToken))

	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid token signature encoding: %w", err)
	}

	err = rsa.VerifyPKCS1v15(public.(*rsa.PublicKey), crypto.SHA256, hashed[:], sig)
	if err != nil {
		return fmt.Errorf("invalid token signature: %w", err)
	}

	return nil
}

func (alg RS256) String() string {
	return "RS256"
}
