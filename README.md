# JWT

JSON Web Token library

![Build Status](https://github.com/nasermirzaei89/jwt/actions/workflows/build.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/nasermirzaei89/jwt)](https://goreportcard.com/report/github.com/nasermirzaei89/jwt)
[![Codecov](https://codecov.io/gh/nasermirzaei89/jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/nasermirzaei89/jwt)
[![Go Reference](https://pkg.go.dev/badge/github.com/nasermirzaei89/jwt.svg)](https://pkg.go.dev/github.com/nasermirzaei89/jwt)
[![License](https://img.shields.io/github/license/nasermirzaei89/jwt)](https://raw.githubusercontent.com/nasermirzaei89/jwt/master/LICENSE)

## Supported Algorithms

* [x] HS256
* [x] HS384
* [x] HS512
* [x] RS256
* [x] RS384
* [x] RS512
* [ ] ES256
* [ ] ES384
* [ ] ES512
* [ ] PS256
* [ ] PS384
* [ ] PS512

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
