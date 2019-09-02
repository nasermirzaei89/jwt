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
	GetIssuer() (string, error)
	SetSubject(sub string)
	GetSubject() (string, error)
	SetAudience(aud ...string)
	GetAudience() ([]string, error)
	SetExpirationTime(exp time.Time)
	GetExpirationTime() (time.Time, error)
	SetNotBefore(nbf time.Time)
	GetNotBefore() (time.Time, error)
	SetIssuedAt(iat time.Time)
	GetIssuedAt() (time.Time, error)
	SetJWTID(jti string)
	GetJWTID() (string, error)
	Set(key string, value interface{})
	Get(key string) (interface{}, error)
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
	//ES256 Algorithm = "ES256"
	//ES384 Algorithm = "ES384"
	//ES512 Algorithm = "ES512"
	//PS256 Algorithm = "PS256"
	//PS384 Algorithm = "PS384"
	//PS512 Algorithm = "PS512"
)

var ErrClaimNotFound = errors.New("claim not found")
var ErrInvalidClaimType = errors.New("invalid claim type")

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

func (t *token) GetIssuer() (string, error) {
	value, ok := t.payload["iss"]
	if !ok {
		return "", ErrClaimNotFound
	}

	iss, ok := value.(string)
	if !ok {
		return "", ErrInvalidClaimType
	}

	return iss, nil
}

func (t *token) SetSubject(sub string) {
	t.Set("sub", sub)
}

func (t *token) GetSubject() (string, error) {
	value, ok := t.payload["sub"]
	if !ok {
		return "", ErrClaimNotFound
	}

	sub, ok := value.(string)
	if !ok {
		return "", ErrInvalidClaimType
	}

	return sub, nil
}

func (t *token) SetAudience(aud ...string) {
	t.Set("aud", aud)
}

func (t *token) GetAudience() ([]string, error) {
	value, ok := t.payload["aud"]
	if !ok {
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

func (t *token) SetExpirationTime(exp time.Time) {
	t.Set("exp", exp.Unix())
}

func (t *token) GetExpirationTime() (time.Time, error) {
	value, ok := t.payload["exp"]
	if !ok {
		return time.Time{}, ErrClaimNotFound
	}

	exp, ok := value.(int64)
	if !ok {
		return time.Time{}, ErrInvalidClaimType
	}

	return time.Unix(exp, 0), nil
}

func (t *token) SetNotBefore(nbf time.Time) {
	t.Set("nbf", nbf.Unix())
}

func (t *token) GetNotBefore() (time.Time, error) {
	value, ok := t.payload["nbf"]
	if !ok {
		return time.Time{}, ErrClaimNotFound
	}

	nbf, ok := value.(int64)
	if !ok {
		return time.Time{}, ErrInvalidClaimType
	}

	return time.Unix(nbf, 0), nil
}

func (t *token) SetIssuedAt(iat time.Time) {
	t.Set("iat", iat.Unix())
}

func (t *token) GetIssuedAt() (time.Time, error) {
	value, ok := t.payload["iat"]
	if !ok {
		return time.Time{}, ErrClaimNotFound
	}

	iat, ok := value.(int64)
	if !ok {
		return time.Time{}, ErrInvalidClaimType
	}

	return time.Unix(iat, 0), nil
}

func (t *token) SetJWTID(jti string) {
	t.Set("jti", jti)
}

func (t *token) GetJWTID() (string, error) {
	value, ok := t.payload["jti"]
	if !ok {
		return "", ErrClaimNotFound
	}

	jti, ok := value.(string)
	if !ok {
		return "", ErrInvalidClaimType
	}

	return jti, nil
}

func (t *token) Set(key string, value interface{}) {
	t.payload[key] = value
}

func (t *token) Get(key string) (interface{}, error) {
	value, ok := t.payload[key]
	if !ok {
		return nil, ErrClaimNotFound
	}
	return value, nil
}

func (t *token) Validate() error {
	exp, err := t.GetExpirationTime()
	if err == nil {
		if exp.Before(time.Now()) {
			return errors.New("token expired")
		}
	}

	nbf, err := t.GetNotBefore()
	if err == nil {
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
func Sign(t Token, key []byte) (string, error) {
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
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(unsignedToken))
		return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
	case HS384:
		mac := hmac.New(sha512.New384, key)
		_, _ = mac.Write([]byte(unsignedToken))
		return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
	case HS512:
		mac := hmac.New(sha512.New, key)
		_, _ = mac.Write([]byte(unsignedToken))
		return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
	case RS256:
		block, _ := pem.Decode(key)
		if block == nil {
			return "", errors.New("invalid pem received")
		}
		private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("error on parse private key: %s", err)
		}

		hashed := sha256.Sum256([]byte(unsignedToken))
		b, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, hashed[:])
		if err != nil {
			return "", fmt.Errorf("error on sign token: %s", err)
		}

		return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(b)), nil
	case RS384:
		block, _ := pem.Decode(key)
		if block == nil {
			return "", errors.New("invalid pem received")
		}
		private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("error on parse private key: %s", err)
		}

		hashed := sha512.Sum384([]byte(unsignedToken))
		b, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA384, hashed[:])
		if err != nil {
			return "", fmt.Errorf("error on sign token: %s", err)
		}

		return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(b)), nil
	case RS512:
		block, _ := pem.Decode(key)
		if block == nil {
			return "", errors.New("invalid pem received")
		}
		private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("error on parse private key: %s", err)
		}

		hashed := sha512.Sum512([]byte(unsignedToken))
		b, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA512, hashed[:])
		if err != nil {
			return "", fmt.Errorf("error on sign token: %s", err)
		}

		return fmt.Sprintf("%s.%s", unsignedToken, base64.RawURLEncoding.EncodeToString(b)), nil
	default:
		return "", errors.New("unsupported algorithm")
	}
}

// Verify token string with secret key
func Verify(t string, key []byte) error {
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
		mac := hmac.New(sha256.New, key)
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
		mac := hmac.New(sha512.New384, key)
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
		mac := hmac.New(sha512.New, key)
		_, _ = mac.Write([]byte(fmt.Sprintf("%s.%s", arr[0], arr[1])))
		sig, err := base64.RawURLEncoding.DecodeString(arr[2])
		if err != nil {
			return fmt.Errorf("invalid token signature encoding: %s", err.Error())
		}
		if !hmac.Equal(mac.Sum(nil), sig) {
			return errors.New("invalid token signature")
		}

		return nil
	case RS256:
		block, _ := pem.Decode(key)
		if block == nil {
			return errors.New("invalid pem received")
		}
		public, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("error on parse public key: %s", err)
		}

		hashed := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", arr[0], arr[1])))

		sig, err := base64.RawURLEncoding.DecodeString(arr[2])
		if err != nil {
			return fmt.Errorf("invalid token signature encoding: %s", err.Error())
		}
		err = rsa.VerifyPKCS1v15(public.(*rsa.PublicKey), crypto.SHA256, hashed[:], sig)
		if err != nil {
			return fmt.Errorf("invalid token signature: %s", err)
		}

		return nil
	case RS384:
		block, _ := pem.Decode(key)
		if block == nil {
			return errors.New("invalid pem received")
		}
		public, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("error on parse public key: %s", err)
		}

		hashed := sha512.Sum384([]byte(fmt.Sprintf("%s.%s", arr[0], arr[1])))

		sig, err := base64.RawURLEncoding.DecodeString(arr[2])
		if err != nil {
			return fmt.Errorf("invalid token signature encoding: %s", err.Error())
		}
		err = rsa.VerifyPKCS1v15(public.(*rsa.PublicKey), crypto.SHA384, hashed[:], sig)
		if err != nil {
			return fmt.Errorf("invalid token signature: %s", err)
		}

		return nil
	case RS512:
		block, _ := pem.Decode(key)
		if block == nil {
			return errors.New("invalid pem received")
		}
		public, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("error on parse public key: %s", err)
		}

		hashed := sha512.Sum512([]byte(fmt.Sprintf("%s.%s", arr[0], arr[1])))

		sig, err := base64.RawURLEncoding.DecodeString(arr[2])
		if err != nil {
			return fmt.Errorf("invalid token signature encoding: %s", err.Error())
		}
		err = rsa.VerifyPKCS1v15(public.(*rsa.PublicKey), crypto.SHA512, hashed[:], sig)
		if err != nil {
			return fmt.Errorf("invalid token signature: %s", err)
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
