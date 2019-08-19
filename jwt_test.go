package jwt_test

import (
	"github.com/nasermirzaei89/jwt"
	"testing"
)

var secret = []byte("secret_key")

func TestSignHS256(t *testing.T) {
	excepted := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.HUfJqC1q8JUPKD4jj8PZAYppSrQRL8tJHTljdcTfFCQ"
	token := jwt.New(jwt.HS256)
	tokenStr, err := jwt.Sign(token, secret)
	if err != nil {
		t.Error(err)
	}

	if tokenStr != excepted {
		t.Errorf("excepted: '%s', got: '%s'", excepted, tokenStr)
	}
}

func TestSignHS384(t *testing.T) {
	excepted := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.Tesq3qahWM2tdkVGIMTRB0uoCV93sZHHZdwcVfwatm-dA6xXVzItk4Y1tkBbP0rT"
	token := jwt.New(jwt.HS384)
	tokenStr, err := jwt.Sign(token, secret)
	if err != nil {
		t.Error(err)
	}

	if tokenStr != excepted {
		t.Errorf("excepted: '%s', got: '%s'", excepted, tokenStr)
	}
}

func TestSignHS512(t *testing.T) {
	excepted := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.A86BXmxG5KZJeJlLLQGQiLFTeVIFWtaavXtgWRFZjhO-XvhLzSkWjVQ42ijGzDrRfz3LClikgNNz_d3tA7NOdw"
	token := jwt.New(jwt.HS512)
	tokenStr, err := jwt.Sign(token, secret)
	if err != nil {
		t.Error(err)
	}

	if tokenStr != excepted {
		t.Errorf("excepted: '%s', got: '%s'", excepted, tokenStr)
	}
}

func TestVerifyInvalidToken(t *testing.T) {
	tokenStr := "invalid"
	err := jwt.Verify(tokenStr, secret)
	if err == nil {
		t.Error("excepted error but got nil")
		return
	}

	excepted := "invalid token provided"
	if err.Error() != excepted {
		t.Errorf("excepted error: %s, got: %s", excepted, err.Error())
	}
}

func TestVerifyHS256(t *testing.T) {
	tokenStr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.HUfJqC1q8JUPKD4jj8PZAYppSrQRL8tJHTljdcTfFCQ"
	err := jwt.Verify(tokenStr, secret)
	if err != nil {
		t.Error(err)
	}
}

func TestVerifyHS384(t *testing.T) {
	tokenStr := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.Tesq3qahWM2tdkVGIMTRB0uoCV93sZHHZdwcVfwatm-dA6xXVzItk4Y1tkBbP0rT"
	err := jwt.Verify(tokenStr, secret)
	if err != nil {
		t.Error(err)
	}
}

func TestVerifyHS512(t *testing.T) {
	tokenStr := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.A86BXmxG5KZJeJlLLQGQiLFTeVIFWtaavXtgWRFZjhO-XvhLzSkWjVQ42ijGzDrRfz3LClikgNNz_d3tA7NOdw"
	err := jwt.Verify(tokenStr, secret)
	if err != nil {
		t.Error(err)
	}
}

func TestParse(t *testing.T) {
	tokenStr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.HUfJqC1q8JUPKD4jj8PZAYppSrQRL8tJHTljdcTfFCQ"
	token, err := jwt.Parse(tokenStr)
	if err != nil {
		t.Error(err)
	}

	if token == nil {
		t.Error("excepted token but got nil")
	}
}
