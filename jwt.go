package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Header is json web token header.
type Header struct {
	Algorithm Algorithm `json:"alg"`
	Type      string    `json:"typ"`
}

const typeJWT = "JWT"

// Payload is json web token payload.
type Payload map[string]interface{}

// Algorithm is json web token algorithm.
type Algorithm string

// Algorithms.
const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	// ES256 Algorithm = "ES256"
	// ES384 Algorithm = "ES384"
	// ES512 Algorithm = "ES512"
	// PS256 Algorithm = "PS256"
	// PS384 Algorithm = "PS384"
	// PS512 Algorithm = "PS512".
)

// Registered Claim Names.
const (
	ClaimIssuer         = "iss"
	ClaimSubject        = "sub"
	ClaimAudience       = "aud"
	ClaimExpirationTime = "exp"
	ClaimNotBefore      = "nbf"
	ClaimIssuedAt       = "iat"
	ClaimJWTID          = "jti"
)

const tokenParts = 3

var (
	ErrClaimNotFound            = errors.New("claim not found")
	ErrInvalidClaimType         = errors.New("invalid claim type")
	ErrTokenExpired             = errors.New("token expired")
	ErrTokenShouldNotBeAccepted = errors.New("token should not be accepted for processing yet")
	ErrInvalidToken             = errors.New("invalid token provided")
	ErrInvalidTokenSignature    = errors.New("invalid token signature")
	ErrUnsupportedAlgorithm     = errors.New("unsupported algorithm")
	ErrUnsupportedTokenType     = errors.New("unsupported token type")
	ErrInvalidPem               = errors.New("invalid pem received")
)

// Token struct.
type Token struct {
	header  Header
	payload Payload
}

func (t Token) GetHeader() Header {
	return t.header
}

func (t Token) GetPayload() Payload {
	return t.payload
}

func (t *Token) SetIssuer(iss string) {
	t.Set(ClaimIssuer, iss)
}

func (t Token) GetIssuer() (string, error) {
	value, exists := t.payload[ClaimIssuer]
	if !exists {
		return "", ErrClaimNotFound
	}

	iss, ok := value.(string)
	if !ok {
		return "", ErrInvalidClaimType
	}

	return iss, nil
}

func (t *Token) SetSubject(sub string) {
	t.Set(ClaimSubject, sub)
}

func (t Token) GetSubject() (string, error) {
	value, exists := t.payload[ClaimSubject]
	if !exists {
		return "", ErrClaimNotFound
	}

	sub, ok := value.(string)
	if !ok {
		return "", ErrInvalidClaimType
	}

	return sub, nil
}

func (t *Token) SetAudience(aud ...string) {
	t.Set(ClaimAudience, aud)
}

func (t Token) GetAudience() ([]string, error) {
	value, exists := t.payload[ClaimAudience]
	if !exists {
		return nil, ErrClaimNotFound
	}

	auds, ok := value.([]string)
	if !ok {
		aud, ok := value.(string)
		if !ok {
			return nil, ErrInvalidClaimType
		}

		return []string{aud}, nil
	}

	return auds, nil
}

func (t *Token) SetExpirationTime(exp time.Time) {
	t.Set(ClaimExpirationTime, exp.Unix())
}

func (t Token) GetExpirationTime() (time.Time, error) {
	value, exists := t.payload[ClaimExpirationTime]
	if !exists {
		return time.Time{}, ErrClaimNotFound
	}

	exp, ok := value.(float64)
	if !ok {
		return time.Time{}, ErrInvalidClaimType
	}

	return time.Unix(int64(exp), 0), nil
}

func (t *Token) SetNotBefore(nbf time.Time) {
	t.Set(ClaimNotBefore, nbf.Unix())
}

func (t Token) GetNotBefore() (time.Time, error) {
	value, exists := t.payload[ClaimNotBefore]
	if !exists {
		return time.Time{}, ErrClaimNotFound
	}

	nbf, ok := value.(float64)
	if !ok {
		return time.Time{}, ErrInvalidClaimType
	}

	return time.Unix(int64(nbf), 0), nil
}

func (t *Token) SetIssuedAt(iat time.Time) {
	t.Set(ClaimIssuedAt, iat.Unix())
}

func (t Token) GetIssuedAt() (time.Time, error) {
	value, exists := t.payload[ClaimIssuedAt]
	if !exists {
		return time.Time{}, ErrClaimNotFound
	}

	iat, ok := value.(float64)
	if !ok {
		return time.Time{}, ErrInvalidClaimType
	}

	return time.Unix(int64(iat), 0), nil
}

func (t *Token) SetJWTID(jti string) {
	t.Set(ClaimJWTID, jti)
}

func (t Token) GetJWTID() (string, error) {
	value, exists := t.payload[ClaimJWTID]
	if !exists {
		return "", ErrClaimNotFound
	}

	jti, ok := value.(string)
	if !ok {
		return "", ErrInvalidClaimType
	}

	return jti, nil
}

func (t *Token) Set(key string, value interface{}) {
	t.payload[key] = value
}

func (t Token) Get(key string) (interface{}, error) {
	value, ok := t.payload[key]
	if !ok {
		return nil, ErrClaimNotFound
	}

	return value, nil
}

func (t Token) Validate() error {
	exp, err := t.GetExpirationTime()
	if err == nil {
		if exp.Before(time.Now()) {
			return ErrTokenExpired
		}
	}

	nbf, err := t.GetNotBefore()
	if err == nil {
		if nbf.After(time.Now()) {
			return ErrTokenShouldNotBeAccepted
		}
	}

	return nil
}

// New returns new json web token.
func New(alg Algorithm) *Token {
	return &Token{
		header: Header{
			Algorithm: alg,
			Type:      typeJWT,
		},
		payload: map[string]interface{}{},
	}
}

// Sign the token with secret key.
func Sign(token Token, key []byte) (string, error) {
	header := token.GetHeader()

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("error on marshal header: %w", err)
	}

	payloadBytes, err := json.Marshal(token.GetPayload())
	if err != nil {
		return "", fmt.Errorf("error on marshal payload: %w", err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsignedToken := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)

	switch header.Algorithm {
	case HS256:
		return signHS256(key, unsignedToken)
	case HS384:
		return signHS384(key, unsignedToken)
	case HS512:
		return signHS512(key, unsignedToken)
	case RS256:
		return signRS256(key, unsignedToken)
	case RS384:
		return signRS384(key, unsignedToken)
	case RS512:
		return signRS512(key, unsignedToken)
	default:
		return "", ErrUnsupportedAlgorithm
	}
}

func signHS256(key []byte, unsignedToken string) (string, error) {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(unsignedToken))

	return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
}

func signHS384(key []byte, unsignedToken string) (string, error) {
	mac := hmac.New(sha512.New384, key)
	_, _ = mac.Write([]byte(unsignedToken))

	return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
}

func signHS512(key []byte, unsignedToken string) (string, error) {
	mac := hmac.New(sha512.New, key)
	_, _ = mac.Write([]byte(unsignedToken))

	return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
}

func signRS256(key []byte, unsignedToken string) (string, error) {
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

func signRS384(key []byte, unsignedToken string) (string, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return "", ErrInvalidPem
	}

	private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("error on parse private key: %w", err)
	}

	hashed := sha512.Sum384([]byte(unsignedToken))

	b, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA384, hashed[:])
	if err != nil {
		return "", fmt.Errorf("error on sign token: %w", err)
	}

	return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(b)), nil
}

func signRS512(key []byte, unsignedToken string) (string, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return "", ErrInvalidPem
	}

	private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("error on parse private key: %w", err)
	}

	hashed := sha512.Sum512([]byte(unsignedToken))

	b, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA512, hashed[:])
	if err != nil {
		return "", fmt.Errorf("error on sign token: %w", err)
	}

	return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(b)), nil
}

// Verify token string with secret key.
func Verify(t string, key []byte) error {
	arr := strings.Split(t, ".")
	if len(arr) != tokenParts {
		return ErrInvalidToken
	}

	var tok Token

	header, err := base64.RawURLEncoding.DecodeString(arr[0])
	if err != nil {
		return fmt.Errorf("invalid token header encoding: %w", err)
	}

	err = json.Unmarshal(header, &tok.header)
	if err != nil {
		return fmt.Errorf("invalid token header: %w", err)
	}

	// https://datatracker.ietf.org/doc/html/rfc7519#section-5.1
	if typ := tok.header.Type; strings.ToUpper(typ) != typeJWT {
		return ErrUnsupportedTokenType
	}

	unsignedToken := fmt.Sprintf("%s.%s", arr[0], arr[1])

	switch tok.header.Algorithm {
	case HS256:
		return verifyHS256(key, unsignedToken, arr[2])
	case HS384:
		return verifyHS384(key, unsignedToken, arr[2])
	case HS512:
		return verifyHS512(key, unsignedToken, arr[2])
	case RS256:
		return verifyRS256(key, unsignedToken, arr[2])
	case RS384:
		return verifyRS384(key, unsignedToken, arr[2])
	case RS512:
		return verifyRS512(key, unsignedToken, arr[2])
	default:
		return ErrUnsupportedAlgorithm
	}
}

func verifyHS256(key []byte, unsignedToken, signature string) error {
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

func verifyHS384(key []byte, unsignedToken, signature string) error {
	mac := hmac.New(sha512.New384, key)
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

func verifyHS512(key []byte, unsignedToken, signature string) error {
	mac := hmac.New(sha512.New, key)
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

func verifyRS256(key []byte, unsignedToken, signature string) error {
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

func verifyRS384(key []byte, unsignedToken, signature string) error {
	block, _ := pem.Decode(key)
	if block == nil {
		return ErrInvalidPem
	}

	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("error on parse public key: %w", err)
	}

	hashed := sha512.Sum384([]byte(unsignedToken))

	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid token signature encoding: %w", err)
	}

	err = rsa.VerifyPKCS1v15(public.(*rsa.PublicKey), crypto.SHA384, hashed[:], sig)
	if err != nil {
		return fmt.Errorf("invalid token signature: %w", err)
	}

	return nil
}

func verifyRS512(key []byte, unsignedToken, signature string) error {
	block, _ := pem.Decode(key)
	if block == nil {
		return ErrInvalidPem
	}

	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("error on parse public key: %w", err)
	}

	hashed := sha512.Sum512([]byte(unsignedToken))

	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid token signature encoding: %w", err)
	}

	err = rsa.VerifyPKCS1v15(public.(*rsa.PublicKey), crypto.SHA512, hashed[:], sig)
	if err != nil {
		return fmt.Errorf("invalid token signature: %w", err)
	}

	return nil
}

// Parse token string without verifying.
func Parse(t string) (*Token, error) {
	arr := strings.Split(t, ".")
	if len(arr) != tokenParts {
		return nil, ErrInvalidToken
	}

	var tok Token

	header, err := base64.RawURLEncoding.DecodeString(arr[0])
	if err != nil {
		return nil, fmt.Errorf("invalid token header encoding: %w", err)
	}

	err = json.Unmarshal(header, &tok.header)
	if err != nil {
		return nil, fmt.Errorf("invalid token header: %w", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(arr[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token payload encoding: %w", err)
	}

	err = json.Unmarshal(payload, &tok.payload)
	if err != nil {
		return nil, fmt.Errorf("invalid token payload: %w", err)
	}

	return &tok, nil
}
