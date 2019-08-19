# JWT

JSON Web Token library

[![Build Status](https://travis-ci.org/nasermirzaei89/jwt.svg?branch=master)](https://travis-ci.org/nasermirzaei89/jwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/nasermirzaei89/jwt)](https://goreportcard.com/report/github.com/nasermirzaei89/jwt)
[![GolangCI](https://golangci.com/badges/github.com/nasermirzaei89/jwt.svg)](https://golangci.com/r/github.com/nasermirzaei89/jwt)
[![Codecov](https://codecov.io/gh/nasermirzaei89/jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/nasermirzaei89/jwt)
[![GoDoc](https://godoc.org/github.com/nasermirzaei89/jwt?status.svg)](https://godoc.org/github.com/nasermirzaei89/jwt)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://raw.githubusercontent.com/nasermirzaei89/jwt/master/LICENSE)

## Usage

### Sign

```go
package main

import (
	"fmt"
	"log"

	"github.com/nasermirzaei89/jwt"
)

func main() {
	token := jwt.New(jwt.HS256)
	tokenStr, err := jwt.Sign(token, []byte("secret_key"))
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(tokenStr) // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.HUfJqC1q8JUPKD4jj8PZAYppSrQRL8tJHTljdcTfFCQ
}
```

### Verify

```go
package main

import (
	"fmt"
	"log"

	"github.com/nasermirzaei89/jwt"
)

func main() {
	tokenStr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.HUfJqC1q8JUPKD4jj8PZAYppSrQRL8tJHTljdcTfFCQ"
    err := jwt.Verify(tokenStr, []byte("secret_key"))
	if err != nil {
		log.Fatalln(err)
	}
}
```


### Sign With Claims

```go
package main

import (
	"fmt"
	"log"
    "time"

	"github.com/nasermirzaei89/jwt"
)

func main() {
	token := jwt.New(jwt.HS256)
    token.SetIssuer("https://yourdomain.tld")
    token.SetExpiresAt(time.Now())
	tokenStr, err := jwt.Sign(token, []byte("secret_key"))
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(tokenStr) // variable
}
```
