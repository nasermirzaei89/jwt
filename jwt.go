package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Header is json web token header
type Header struct {
	Algorithm Algorithm `json:"alg"`
	Type      string    `json:"typ"`
}

// Payload is json web token payload
type Payload map[string]interface{}

// Token interface
type Token interface {
	SetIssuer(iss string)
	GetIssuer() (string, bool)
	SetSubject(sub string)
	GetSubject() (string, bool)
	SetAudience(aud ...string)
	GetAudience() ([]string, bool)
	SetExpiresAt(exp time.Time)
	GetExpiresAt() (time.Time, bool)
	SetNotBefore(nbf time.Time)
	GetNotBefore() (time.Time, bool)
	SetIssuedAt(iat time.Time)
	GetIssuedAt() (time.Time, bool)
	SetJWTID(jti string)
	GetJWTID() (string, bool)
	Set(key string, value interface{})
	Get(key string) (interface{}, bool)
	Validate() error
}

// Algorithm type
type Algorithm string

// Algorithms
const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
)

type token struct {
	header  Header
	payload Payload
}

func (t *token) GetHeader() Header {
	return t.header
}

func (t *token) GetPayload() Payload {
	return t.payload
}

func (t *token) SetIssuer(iss string) {
	t.Set("iss", iss)
}

func (t *token) GetIssuer() (string, bool) {
	value, ok := t.Get("iss")
	if !ok {
		return "", false
	}

	iss, ok := value.(string)
	if !ok {
		return "", false
	}

	return iss, true
}

func (t *token) SetSubject(sub string) {
	t.Set("sub", sub)
}

func (t *token) GetSubject() (string, bool) {
	value, ok := t.Get("sub")
	if !ok {
		return "", false
	}

	sub, ok := value.(string)
	if !ok {
		return "", false
	}

	return sub, true
}

func (t *token) SetAudience(aud ...string) {
	t.Set("aud", aud)
}

func (t *token) GetAudience() ([]string, bool) {
	value, ok := t.Get("aud")
	if !ok {
		return nil, false
	}

	auds, ok := value.([]string)
	if !ok {
		aud, ok := value.(string)
		if !ok {
			return nil, false
		}

		return []string{aud}, true
	}

	return auds, true
}

func (t *token) SetExpiresAt(exp time.Time) {
	t.Set("exp", exp.Unix())
}

func (t *token) GetExpiresAt() (time.Time, bool) {
	value, ok := t.Get("exp")
	if !ok {
		return time.Time{}, false
	}

	exp, ok := value.(int64)
	if !ok {
		return time.Time{}, false
	}

	return time.Unix(exp, 0), true
}

func (t *token) SetNotBefore(nbf time.Time) {
	t.Set("nbf", nbf.Unix())
}

func (t *token) GetNotBefore() (time.Time, bool) {
	value, ok := t.Get("nbf")
	if !ok {
		return time.Time{}, false
	}

	nbf, ok := value.(int64)
	if !ok {
		return time.Time{}, false
	}

	return time.Unix(nbf, 0), true
}

func (t *token) SetIssuedAt(iat time.Time) {
	t.Set("iat", iat.Unix())
}

func (t *token) GetIssuedAt() (time.Time, bool) {
	value, ok := t.Get("iat")
	if !ok {
		return time.Time{}, false
	}

	iat, ok := value.(int64)
	if !ok {
		return time.Time{}, false
	}

	return time.Unix(iat, 0), true
}

func (t *token) SetJWTID(jti string) {
	t.Set("jti", jti)
}

func (t *token) GetJWTID() (string, bool) {
	value, ok := t.Get("jti")
	if !ok {
		return "", false
	}

	jti, ok := value.(string)
	if !ok {
		return "", false
	}

	return jti, true
}

func (t *token) Set(key string, value interface{}) {
	t.payload["key"] = value
}

func (t *token) Get(key string) (interface{}, bool) {
	value, ok := t.payload[key]
	return value, ok
}

func (t *token) Validate() error {
	if exp, ok := t.GetExpiresAt(); ok {
		if exp.Before(time.Now()) {
			return errors.New("token expired")
		}
	}

	if nbf, ok := t.GetNotBefore(); ok {
		if nbf.After(time.Now()) {
			return errors.New("token should not be accepted for processing yet")
		}
	}

	return nil
}

// New returns new json web token
func New(alg Algorithm) Token {
	return &token{
		header: Header{
			Algorithm: alg,
			Type:      "JWT",
		},
		payload: map[string]interface{}{},
	}
}

// Sign the token with secret key
func Sign(t Token, secret []byte) (string, error) {
	h := t.(interface{ GetHeader() Header }).GetHeader()
	header, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("error on marshal header: %s", err.Error())
	}

	payload, err := json.Marshal(t.(interface{ GetPayload() Payload }).GetPayload())
	if err != nil {
		return "", fmt.Errorf("error on marshal payload: %s", err.Error())
	}

	unsignedToken := fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString(header), base64.RawURLEncoding.EncodeToString(payload))

	switch h.Algorithm {
	case HS256:
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(unsignedToken))
		return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
	case HS384:
		mac := hmac.New(sha512.New384, secret)
		_, _ = mac.Write([]byte(unsignedToken))
		return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
	case HS512:
		mac := hmac.New(sha512.New, secret)
		_, _ = mac.Write([]byte(unsignedToken))
		return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
	default:
		return "", errors.New("unsupported algorithm")
	}
}

// Verify token string with secret key
func Verify(t string, secret []byte) error {
	arr := strings.Split(t, ".")
	if len(arr) != 3 {
		return errors.New("invalid token provided")
	}

	tok := token{}

	header, err := base64.RawURLEncoding.DecodeString(arr[0])
	if err != nil {
		return fmt.Errorf("invalid token header encoding: %s", err.Error())
	}

	err = json.Unmarshal(header, &tok.header)
	if err != nil {
		return fmt.Errorf("invalid token header: %s", err.Error())
	}

	if typ := tok.header.Type; typ != "JWT" {
		return fmt.Errorf("unsupported token type: %s", typ)
	}

	switch tok.header.Algorithm {
	case HS256:
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(fmt.Sprintf("%s.%s", arr[0], arr[1])))
		sig, err := base64.RawURLEncoding.DecodeString(arr[2])
		if err != nil {
			return fmt.Errorf("invalid token signature encoding: %s", err.Error())
		}
		if !hmac.Equal(mac.Sum(nil), sig) {
			return errors.New("invalid token signature")
		}

		return nil
	case HS384:
		mac := hmac.New(sha512.New384, secret)
		_, _ = mac.Write([]byte(fmt.Sprintf("%s.%s", arr[0], arr[1])))
		sig, err := base64.RawURLEncoding.DecodeString(arr[2])
		if err != nil {
			return fmt.Errorf("invalid token signature encoding: %s", err.Error())
		}
		if !hmac.Equal(mac.Sum(nil), sig) {
			return errors.New("invalid token signature")
		}

		return nil
	case HS512:
		mac := hmac.New(sha512.New, secret)
		_, _ = mac.Write([]byte(fmt.Sprintf("%s.%s", arr[0], arr[1])))
		sig, err := base64.RawURLEncoding.DecodeString(arr[2])
		if err != nil {
			return fmt.Errorf("invalid token signature encoding: %s", err.Error())
		}
		if !hmac.Equal(mac.Sum(nil), sig) {
			return errors.New("invalid token signature")
		}

		return nil
	default:
		return errors.New("unsupported algorithm")
	}
}

// Parse token string without verifying
func Parse(t string) (Token, error) {
	arr := strings.Split(t, ".")
	if len(arr) != 3 {
		return nil, errors.New("invalid token provided")
	}

	tok := token{}

	header, err := base64.RawURLEncoding.DecodeString(arr[0])
	if err != nil {
		return nil, fmt.Errorf("invalid token header encoding: %s", err.Error())
	}

	err = json.Unmarshal(header, &tok.header)
	if err != nil {
		return nil, fmt.Errorf("invalid token header: %s", err.Error())
	}

	payload, err := base64.RawURLEncoding.DecodeString(arr[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token payload encoding: %s", err.Error())
	}

	err = json.Unmarshal(payload, &tok.payload)
	if err != nil {
		return nil, fmt.Errorf("invalid token payload: %s", err.Error())
	}

	return &tok, nil
}
