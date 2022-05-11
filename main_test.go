package main

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Crypted password
const globBcrypt0000 = "$2a$05$5Q7AIdXjMaiCnd2VZYNlke7PskIgXNaaOKrUVIa787VUU5L5usooG"
const globBcrypt1111 = "$2a$05$JQKwvqAyG1SzDEr.jkp3Ke1YEDwt1XVkrvjG/0bj5eb8o9CHX0VWi"

// Ip
const globValidIp = "1.2.3.4" // valid in jwt
const globOtherIp = "4.3.2.1" // invalid in jwt

// Form and Header data
const globUsername = "Test"
const globPassword = "0000"
const globPasswordH = "1111" // for header
const globAction = "none"
const globCsrf = "none"
const globDataNoUsername = "action=" + globAction + "&csrf=" + globCsrf
const globDataNoPassword = "username=" + globUsername + "&action=" + globAction + "&csrf=" + globCsrf
const globDataInvalid = "username=A" + "&password=B" + "&action=C" + "&csrf=D"
const globData = "username=" + globUsername + "&password=" + globPassword + "&action=" + globAction + "&csrf=" + globCsrf
const globDataH = "username=" + globUsername + "H&password=" + globPasswordH + "&action=" + globAction + "H&csrf=" + globCsrf + "H"

const globCookieName = "COOK"

var headersCredentials = map[string]*http.Header{
	"fake":       {"fake": []string{"FAKE"}},
	"nousername": {"Auth-Form": []string{globDataNoUsername}},
	"nopassword": {"Auth-Form": []string{globDataNoPassword}},
	"invalid":    {"Auth-Form": []string{globDataInvalid}},
	"valid":      {"Auth-Form": []string{globData}},
	"validH":     {"Auth-Form": []string{globDataH}},
}

/*
{
  "alg": "HS256", // none for badalgo
  "typ": "JWT"
}
{
  "Username": "Test", // Tekt for altered (and bad signature)
  "Ip": "1.2.3.4", // 8.5.7.5 for invalid ip
  "iss": "gfa",
  "aud": [
    "https://localhost"
  ],
  "exp": 9999999999, // 2 for expired
  "nbf": 1,
  "iat": 1,
  "jti": "e4Qve3yxpRLfWD8TDhYLddXbyRiVwCtaex2uT7Zq"
}
*/
var cookiesClaims = map[string]*http.Cookie{
	"fake":      {Name: globCookieName, Value: "FAKE"},
	"badalgo":   {Name: globCookieName, Value: "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJpc3MiOiJnZmEiLCJhdWQiOlsiaHR0cHM6Ly9sb2NhbGhvc3QiXSwiZXhwIjo5OTk5OTk5OTk5LCJuYmYiOjEsImlhdCI6MSwianRpIjoiZTRRdmUzeXhwUkxmV0Q4VERoWUxkZFhieVJpVndDdGFleDJ1VDdacSJ9.WywXK85ZPjbKwvhviTXcyHOfKMH4gsaPAjHQN_kF-z4"},
	"altered":   {Name: globCookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRla3QiLCJJcCI6IjEuMi4zLjQiLCJpc3MiOiJnZmEiLCJhdWQiOlsiaHR0cHM6Ly9sb2NhbGhvc3QiXSwiZXhwIjoyLCJuYmYiOjEsImlhdCI6MSwianRpIjoiZTRRdmUzeXhwUkxmV0Q4VERoWUxkZFhieVJpVndDdGFleDJ1VDdacSJ9.qPYxT0mlE9uKorGLdLC6FLYFjAeRlH56-pVl75PnRyF"},
	"expired":   {Name: globCookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJpc3MiOiJnZmEiLCJhdWQiOlsiaHR0cHM6Ly9sb2NhbGhvc3QiXSwiZXhwIjoyLCJuYmYiOjEsImlhdCI6MSwianRpIjoiZTRRdmUzeXhwUkxmV0Q4VERoWUxkZFhieVJpVndDdGFleDJ1VDdacSJ9.qPYxT0mlE9uKorGLdLC6FLYFjAeRlH56-pVl75PnRyE"},
	"invalidIp": {Name: globCookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjguNS43LjUiLCJpc3MiOiJnZmEiLCJhdWQiOlsiaHR0cHM6Ly9sb2NhbGhvc3QiXSwiZXhwIjo5OTk5OTk5OTk5LCJuYmYiOjEsImlhdCI6MSwianRpIjoiZTRRdmUzeXhwUkxmV0Q4VERoWUxkZFhieVJpVndDdGFleDJ1VDdacSJ9.tUHEqbShd0AyNtLPoUCbOQ4b1ZL-ROhh3C-RGVHCq84"},
	"valid":     {Name: globCookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJpc3MiOiJnZmEiLCJhdWQiOlsiaHR0cHM6Ly9sb2NhbGhvc3QiXSwiZXhwIjo5OTk5OTk5OTk5LCJuYmYiOjEsImlhdCI6MSwianRpIjoiZTRRdmUzeXhwUkxmV0Q4VERoWUxkZFhieVJpVndDdGFleDJ1VDdacSJ9.WywXK85ZPjbKwvhviTXcyHOfKMH4gsaPAjHQN_kF-z4"},
}

var claims = Claims{
	Username: globUsername,
	Ip:       globValidIp,
	RegisteredClaims: jwt.RegisteredClaims{
		ID:        "999",
		ExpiresAt: jwt.NewNumericDate(time.Unix(999999999999999999, 0)),
		Issuer:    "ISSUER",
		Audience:  jwt.ClaimStrings{"http://localhost"},
		IssuedAt:  jwt.NewNumericDate(time.Unix(1, 0)),
		NotBefore: jwt.NewNumericDate(time.Unix(1, 0)),
	},
}
var credentials = Credentials{
	Username: globUsername,
	Password: globPassword,
	Action:   globAction,
	Csrf:     globCsrf,
}

func TestMain(m *testing.M) {
	configuration.Tls = false
	configuration.Port = 80
	configuration.CookieName = globCookieName
	configuration.CookieDomain = "localhost"
	configuration.TokenExpire = 10
	configuration.TokenRefresh = 2
	configuration.JwtKey = []byte("12345")
	configuration.HtmlFile = "./default.index.html"
	configuration.HashCost = 5
	configuration.Users = map[string]string{globUsername: globBcrypt0000, globUsername + "H": globBcrypt1111}

	os.Exit(m.Run())
}
