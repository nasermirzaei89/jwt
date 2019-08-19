# JWT

JWT Token library

[![Build Status](https://travis-ci.org/nasermirzaei89/jwt.svg?branch=master)](https://travis-ci.org/nasermirzaei89/jwt)

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
