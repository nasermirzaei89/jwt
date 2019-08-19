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
