package jwt_test

import (
	"errors"
	"testing"

	"github.com/nasermirzaei89/jwt"
)

var secret = []byte("secret_key")

var private = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxuqRXco9YP2YpBhWR0KtcsJg/2e1hFUQG0AXb+zIXlcvi5+v
2ZVVGG4gcvHCiA+8CSn+qnqM+guaws6/z3WaPQOF5jfrgGdz9RQuiTAnBp0rlDCO
AB56zJAQZKBQWX28Kl1nNrxNY+DdQI8g4apoGjv84WTPq/BXC0wGfsiJvBnme5iL
TWjojyN3k0cGmP3qa4PboxSRlkV9lZY32ovkZpKHun+jbTLc8hL91ZnQ1lJInq4V
WCd5LG6irCQZxEgrh1J90TOjX+/Pb2zIV8s9YgJsQdk8AOg/c+hpRgRDU2Wi8fo0
XBooaYtRBVdH78yL5HeYa38EDu6/JNYWCtvWzQIDAQABAoIBAB+J24iKY1b4fnYu
Iafky4lxhl2YfPBBaG9Zpx2o5lAG9NPnesM96SMZeu2epWBbVk4BqY4wJiATLPOM
Ql9LXywjXdyVqzJNtNX74DECQH3M97bkR+9+5at/gAnkXTkDNY1mB9Jm4sJeSdZN
m0IMebsHHd5C1KaHUdXJtRHvC9+V16mZaxJPmooyXIWY514+/YNHg8fcoWlX/3Pl
XBdZF6dSH8G+oAbcpjF5EckcLHv1WQOltFy1eaPDRjpWpkcmTXIASdmz/YTlC1kF
J7K928Pe73OoCPN9k2xo0DVFocNtR9WRMuBtukE+YNubngJ03JbMWKKNNexVSG7B
3uJNFAUCgYEA/XaCHwYdCdTHCQt5LlgzWZ/vqe478kwmYf8XyIQgCTAvPdx2ItS2
uEBMSOCAezh+rHTqd7vE0m6B0B9IUMvhIRd39yggMhT4xBlaG+APaphDN4Yhma2n
di67Vj8Wj848BhdgTthiQVWAOBCAXijo1DjCdrTuUt6TNynrVf098/MCgYEAyOhJ
COzjPdru52YwasON15HhCNl4iEeMmSnsrzpOalduX4a3GSJV1PeQxU/P86IReTQq
8RgwVagZXaiaPHjeXcaB6VSmXtFxYln6UJ/nBhBQVTbp2nWValhpWFpHR4k5/VwQ
9G3NLAMzbN6OZGRYiykcJtcQmB62a/ebsyn5ej8CgYAOBAed/5CLgqCe92t0DJyK
UDXIh8v40g0tThXamLPMzkVOfmpp8qlH9wZA4Wk5Zx5aGvz8Mf3oRQQYpiIxlZSV
Z97SY/2jx1UaQuygrfssQc81us0Q2nFwL5VcZ5Cv0w+upoxEz+JfCoNUllUC3/BA
DAN03PxwyK4LVt4UmzRZ0QKBgBMBpqcpgfYAGEnb6Qiwp2KVcmyb5kM+QZbb2IBb
S7/TtaVj4T6HeQdExHVmL44k7vJAdS+J0kjINl4d7Tl7Vc4ZUYD5eSPPPKLJUF0A
Q6LXOEJXh5gbN59v7cdmAwhJeyr04sW8/YQEaYELLP1iYN4JbZhfEDrT7P4Z1qkE
d42RAoGAbpDqWt2fjgXXrh9SRsFJ0aHB30gCxIYYj0V3wFsNR6sC/CiOGiVL2HYM
+kGtJyOeKxKQNod/swnchQOh/NcGG69hjgZ/uJxl8NiNBU05siTXvsA+BxS9BDrW
/mEfwBd4cWXBHvFmRQ70IpmD6vE22MrpGAun1pkYCwbsinSb9Jg=
-----END RSA PRIVATE KEY-----
`)

var public = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxuqRXco9YP2YpBhWR0Kt
csJg/2e1hFUQG0AXb+zIXlcvi5+v2ZVVGG4gcvHCiA+8CSn+qnqM+guaws6/z3Wa
PQOF5jfrgGdz9RQuiTAnBp0rlDCOAB56zJAQZKBQWX28Kl1nNrxNY+DdQI8g4apo
Gjv84WTPq/BXC0wGfsiJvBnme5iLTWjojyN3k0cGmP3qa4PboxSRlkV9lZY32ovk
ZpKHun+jbTLc8hL91ZnQ1lJInq4VWCd5LG6irCQZxEgrh1J90TOjX+/Pb2zIV8s9
YgJsQdk8AOg/c+hpRgRDU2Wi8fo0XBooaYtRBVdH78yL5HeYa38EDu6/JNYWCtvW
zQIDAQAB
-----END PUBLIC KEY-----
`)

func TestSign(t *testing.T) {
	t.Parallel()

	t.Run("Sign invalid algorithm", func(t *testing.T) {
		t.Parallel()

		excepted := ""

		token := jwt.New("foo")

		tokenStr, err := jwt.Sign(*token, secret)
		if err == nil {
			t.Error("excepted error but got nil")
		}

		if !errors.Is(err, jwt.ErrUnsupportedAlgorithm) {
			t.Error(err)
		}

		if tokenStr != excepted {
			t.Errorf("excepted: %q, got: %q", excepted, tokenStr)
		}
	})

	t.Run("Sign HS256", func(t *testing.T) {
		t.Parallel()

		excepted := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.HUfJqC1q8JUPKD4jj8PZAYppSrQRL8tJHTljdcTfFCQ"
		token := jwt.New(jwt.HS256)

		tokenStr, err := jwt.Sign(*token, secret)
		if err != nil {
			t.Error(err)
		}

		if tokenStr != excepted {
			t.Errorf("excepted: %q, got: %q", excepted, tokenStr)
		}
	})

	t.Run("Sign HS384", func(t *testing.T) {
		t.Parallel()

		excepted := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.Tesq3qahWM2tdkVGIMTRB0uoCV93sZHHZdwcVfwatm-dA6xXVzItk4Y1tkBbP0rT"
		token := jwt.New(jwt.HS384)

		tokenStr, err := jwt.Sign(*token, secret)
		if err != nil {
			t.Error(err)
		}

		if tokenStr != excepted {
			t.Errorf("excepted: %q, got: %q", excepted, tokenStr)
		}
	})

	t.Run("Sign HS512", func(t *testing.T) {
		t.Parallel()

		excepted := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.A86BXmxG5KZJeJlLLQGQiLFTeVIFWtaavXtgWRFZjhO-XvhLzSkWjVQ42ijGzDrRfz3LClikgNNz_d3tA7NOdw"
		token := jwt.New(jwt.HS512)

		tokenStr, err := jwt.Sign(*token, secret)
		if err != nil {
			t.Error(err)
		}

		if tokenStr != excepted {
			t.Errorf("excepted: %q, got: %q", excepted, tokenStr)
		}
	})

	t.Run("Sign RS256", func(t *testing.T) {
		t.Parallel()

		excepted := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.B1Q-D-h1NW2DbAippP-l6H9YHX22HnZZl15PHO7CC6K0ZcbnOr0IjnyOZFeLUB-02z3ausdsWn7FlZj_juqRfeIlpP7ysJwp0kPGpGJqXE-YlrOrR_KRcs7EjIb53ICV76WPP149h_qu57hIYAlJwSZgy77wkXKoq73psXI0ZAl_0YC7kgGyz_aE7Wwk3-BLcEqhKyC6yG4RoBzqHJgZXEShYUkCWjdwa5O3ogQ0-dMtjp3jXG-l42RaOJqqNYNegBstQWL874hfYQcVxuWdTeBtqTqXsGp2sH60NEd5h6Z-3Ef0nw0bbCTK0ustCHZn5RN4HHvCiazriqK4CdkPrw"

		token := jwt.New(jwt.RS256)

		tokenStr, err := jwt.Sign(*token, private)
		if err != nil {
			t.Error(err)
		}

		if tokenStr != excepted {
			t.Errorf("excepted: %q, got: %q", excepted, tokenStr)
		}
	})

	t.Run("Sign RS256 with invalid key", func(t *testing.T) {
		t.Parallel()

		excepted := ""

		token := jwt.New(jwt.RS256)

		tokenStr, err := jwt.Sign(*token, []byte(""))
		if err == nil {
			t.Error("excepted error but got nil")

			return
		}

		if !errors.Is(err, jwt.ErrInvalidPem) {
			t.Error(err)
		}

		if tokenStr != excepted {
			t.Errorf("excepted: %q, got: %q", excepted, tokenStr)
		}
	})

	t.Run("Sign RS384", func(t *testing.T) {
		t.Parallel()

		excepted := "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.e30.VUugIiYP9KU8jPfYpWtLm3l2iYnM6z09pEPvlkYd4gs72AzBn-vkklhPSn31RO2fH9Xnu6cfL975Zd_kEZKCC0zKZlkmT1GC2b_UKK6kR_iwMdLMIcdtiDKjZK6svPV9AcPGxBZWQh98gznBwNphfkCsZzq0WriSkHbiRA7N7WbwcZt4SPjG76uM4TWBHwBf62AJ9rHFrtt05J0sSzFUqRZe32f_NehvmpY9wLQ4wA4pmzbYe9pR0iY0D-TZ0G5uFiwG10mh8EARi5VCpNgVsziX3B4mAlTj5369DbAeEGw9f_iNqDPhWbshoCpiv94Z4V3bgWT0c7pYP2Sfam6zWQ"
		token := jwt.New(jwt.RS384)

		tokenStr, err := jwt.Sign(*token, private)
		if err != nil {
			t.Error(err)
		}

		if tokenStr != excepted {
			t.Errorf("excepted: %q, got: %q", excepted, tokenStr)
		}
	})

	t.Run("Sign RS384 with invalid key", func(t *testing.T) {
		t.Parallel()

		excepted := ""

		token := jwt.New(jwt.RS384)

		tokenStr, err := jwt.Sign(*token, []byte(""))
		if err == nil {
			t.Error("excepted error but got nil")

			return
		}

		if !errors.Is(err, jwt.ErrInvalidPem) {
			t.Error(err)
		}

		if tokenStr != excepted {
			t.Errorf("excepted: %q, got: %q", excepted, tokenStr)
		}
	})

	t.Run("Sign RS512", func(t *testing.T) {
		t.Parallel()

		excepted := "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.e30.TAc6Fs7zC82s2CwCp8Y7flotPYpnrn0PzZImM3QH9uMfw-I8xySlVosKe9VyQ6CPuO8BWmkW5t9GD4QoN8glKW_bTTBQGM0eLTftSQoUVn8djQkWzCPjol3RWbZvBs6k9RphUF3qibzL9DOYCn8Vsmrwj9RhzDAs1dpeBzEqC_mxtxWDW8rnetp3Kwj2cDZjRPUi9IPFL6ccbvfC9CxsXhrMKccUzb4Yw9YukvuO93QNN_pPCazQFY2zCL2yvBvUpPbHnOdGCX41z_TZY1P7sea5SsGcGv5YOCxKdVTPF3WRhaUhOkY7-AAqMuJZbWxkhkE1OjBwgWj-L28nTKOwVw"
		token := jwt.New(jwt.RS512)

		tokenStr, err := jwt.Sign(*token, private)
		if err != nil {
			t.Error(err)
		}

		if tokenStr != excepted {
			t.Errorf("excepted: %q, got: %q", excepted, tokenStr)
		}
	})

	t.Run("Sign RS512 with invalid key", func(t *testing.T) {
		t.Parallel()

		excepted := ""

		token := jwt.New(jwt.RS512)

		tokenStr, err := jwt.Sign(*token, []byte(""))
		if err == nil {
			t.Error("excepted error but got nil")

			return
		}

		if !errors.Is(err, jwt.ErrInvalidPem) {
			t.Error(err)
		}

		if tokenStr != excepted {
			t.Errorf("excepted: %q, got: %q", excepted, tokenStr)
		}
	})
}

func TestVerify(t *testing.T) {
	t.Parallel()

	t.Run("Verify invalid token", func(t *testing.T) {
		t.Parallel()

		tokenStr := "invalid"

		err := jwt.Verify(tokenStr, secret)
		if err == nil {
			t.Error("excepted error but got nil")

			return
		}

		if !errors.Is(err, jwt.ErrInvalidToken) {
			t.Error(err)
		}
	})

	t.Run("Verify invalid type", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.e30.DYbUWU7uDaI6uT9JmftppmfaWMpSeynd5dqmW3qBOac"

		err := jwt.Verify(tokenStr, secret)
		if err == nil {
			t.Error("excepted error but got nil")

			return
		}

		if !errors.Is(err, jwt.ErrUnsupportedTokenType) {
			t.Error(err)
		}
	})

	t.Run("Verify HS256", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.HUfJqC1q8JUPKD4jj8PZAYppSrQRL8tJHTljdcTfFCQ"

		err := jwt.Verify(tokenStr, secret)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Verify HS256 with invalid signature", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.ZGV2aWwK"

		err := jwt.Verify(tokenStr, secret)
		if err == nil {
			t.Error("excepted error but got nil")

			return
		}

		if !errors.Is(err, jwt.ErrInvalidTokenSignature) {
			t.Error(err)
		}
	})

	t.Run("Verify HS384", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.Tesq3qahWM2tdkVGIMTRB0uoCV93sZHHZdwcVfwatm-dA6xXVzItk4Y1tkBbP0rT"

		err := jwt.Verify(tokenStr, secret)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Verify HS384 with invalid signature", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.ZGV2aWwK"

		err := jwt.Verify(tokenStr, secret)
		if err == nil {
			t.Error("excepted error but got nil")

			return
		}

		if !errors.Is(err, jwt.ErrInvalidTokenSignature) {
			t.Error(err)
		}
	})

	t.Run("Verify HS512", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.A86BXmxG5KZJeJlLLQGQiLFTeVIFWtaavXtgWRFZjhO-XvhLzSkWjVQ42ijGzDrRfz3LClikgNNz_d3tA7NOdw"

		err := jwt.Verify(tokenStr, secret)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Verify HS512 with invalid signature", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.ZGV2aWwK"

		err := jwt.Verify(tokenStr, secret)
		if err == nil {
			t.Error("excepted error but got nil")

			return
		}

		if !errors.Is(err, jwt.ErrInvalidTokenSignature) {
			t.Error(err)
		}
	})

	t.Run("Verify RS256", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.B1Q-D-h1NW2DbAippP-l6H9YHX22HnZZl15PHO7CC6K0ZcbnOr0IjnyOZFeLUB-02z3ausdsWn7FlZj_juqRfeIlpP7ysJwp0kPGpGJqXE-YlrOrR_KRcs7EjIb53ICV76WPP149h_qu57hIYAlJwSZgy77wkXKoq73psXI0ZAl_0YC7kgGyz_aE7Wwk3-BLcEqhKyC6yG4RoBzqHJgZXEShYUkCWjdwa5O3ogQ0-dMtjp3jXG-l42RaOJqqNYNegBstQWL874hfYQcVxuWdTeBtqTqXsGp2sH60NEd5h6Z-3Ef0nw0bbCTK0ustCHZn5RN4HHvCiazriqK4CdkPrw"

		err := jwt.Verify(tokenStr, public)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Verify RS256 with invalid signature", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.ZGV2aWwK"

		err := jwt.Verify(tokenStr, public)
		if err == nil {
			t.Error("excepted error but got nil")

			return
		}

		if !errors.Is(err, jwt.ErrInvalidTokenSignature) {
			t.Error(err)
		}
	})

	t.Run("Verify RS384", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.e30.VUugIiYP9KU8jPfYpWtLm3l2iYnM6z09pEPvlkYd4gs72AzBn-vkklhPSn31RO2fH9Xnu6cfL975Zd_kEZKCC0zKZlkmT1GC2b_UKK6kR_iwMdLMIcdtiDKjZK6svPV9AcPGxBZWQh98gznBwNphfkCsZzq0WriSkHbiRA7N7WbwcZt4SPjG76uM4TWBHwBf62AJ9rHFrtt05J0sSzFUqRZe32f_NehvmpY9wLQ4wA4pmzbYe9pR0iY0D-TZ0G5uFiwG10mh8EARi5VCpNgVsziX3B4mAlTj5369DbAeEGw9f_iNqDPhWbshoCpiv94Z4V3bgWT0c7pYP2Sfam6zWQ"

		err := jwt.Verify(tokenStr, public)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Verify RS384 with invalid signature", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.e30.ZGV2aWwK"

		err := jwt.Verify(tokenStr, public)
		if err == nil {
			t.Error("excepted error but got nil")

			return
		}

		if !errors.Is(err, jwt.ErrInvalidTokenSignature) {
			t.Error(err)
		}
	})

	t.Run("Verify RS512", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.e30.TAc6Fs7zC82s2CwCp8Y7flotPYpnrn0PzZImM3QH9uMfw-I8xySlVosKe9VyQ6CPuO8BWmkW5t9GD4QoN8glKW_bTTBQGM0eLTftSQoUVn8djQkWzCPjol3RWbZvBs6k9RphUF3qibzL9DOYCn8Vsmrwj9RhzDAs1dpeBzEqC_mxtxWDW8rnetp3Kwj2cDZjRPUi9IPFL6ccbvfC9CxsXhrMKccUzb4Yw9YukvuO93QNN_pPCazQFY2zCL2yvBvUpPbHnOdGCX41z_TZY1P7sea5SsGcGv5YOCxKdVTPF3WRhaUhOkY7-AAqMuJZbWxkhkE1OjBwgWj-L28nTKOwVw"

		err := jwt.Verify(tokenStr, public)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Verify RS512 with invalid signature", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.e30.ZGV2aWwK"

		err := jwt.Verify(tokenStr, public)
		if err == nil {
			t.Error("excepted error but got nil")

			return
		}

		if !errors.Is(err, jwt.ErrInvalidTokenSignature) {
			t.Error(err)
		}
	})
}

func TestParse(t *testing.T) {
	t.Parallel()

	t.Run("Empty", func(t *testing.T) {
		t.Parallel()

		tokenStr := ""

		token, err := jwt.Parse(tokenStr)
		if err == nil {
			t.Errorf("expected error but got nil")
		}

		if !errors.Is(err, jwt.ErrInvalidToken) {
			t.Error(err)
		}

		if token != nil {
			t.Errorf("excepted nil but got '%T'", token)
		}
	})

	t.Run("Valid HS256", func(t *testing.T) {
		t.Parallel()

		tokenStr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.HUfJqC1q8JUPKD4jj8PZAYppSrQRL8tJHTljdcTfFCQ"

		token, err := jwt.Parse(tokenStr)
		if err != nil {
			t.Error(err)
		}

		if token == nil {
			t.Error("excepted token but got nil")
		}
	})
}
