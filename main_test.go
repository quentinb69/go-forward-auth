package main

import (
	"testing"
	"os"
	"net/http"

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
const globData = "username=" + globUsername + "&password=" + globPassword + "&action=" + globAction + "&csrf=" + globCsrf
const globDataHeader = "username=" + globUsername + "H&password=" + globPasswordH + "&action=" + globAction + "H&csrf=" + globCsrf + "H"

const globCookieName = "COOK"
var cookies = map[string]http.Cookie{
	"fake":      http.Cookie{Name: globCookieName, Value: "FAKE"},
	"badAlgo":   http.Cookie{Name: globCookieName, Value: "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjowLCJpYXQiOjAsImlzcyI6ImdmYSIsIm5iZiI6MH0.944b3a4a8fa6251bec89af3dba2c6eeca61e2851a13888091d9e0d3ac3af725e"},
	"altered":   http.Cookie{Name: globCookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjowLCJpYXQiOjAsImlzcyI6ImdmYSIsIm5iZiI6MH0.QQoUNk38fbh31jWtuPvySLplseAZbT_rSkt4fUpxE6A"},
	"expired":   http.Cookie{Name: globCookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjoxLCJpYXQiOjEsImlzcyI6ImdmYSIsIm5iZiI6MX0.NGHH08MV5QoW0mYN7M-dCeytccTkD9vTg8ZhP-jdeOI"},
	"invalidIp": http.Cookie{Name: globCookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjguNS43LjUiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjAsImlzcyI6ImdmYSIsIm5iZiI6MH0.7Z18-wmkmjvQtgTJwDi7Mag4PrmuEa4oPO78M1tVEAQ"},
	"valid":     http.Cookie{Name: globCookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjAsImlzcyI6ImdmYSIsIm5iZiI6MH0.XWcP6GTn3AOcClc5vZMAp3D-MLNNZX1M08p5rG9RdLY"},
}

var claims = Claims{
	Username: globUsername,
	Ip:       globValidIp,
	StandardClaims: jwt.StandardClaims{
		ExpiresAt: 99999999,
		Issuer:    "ISSUER",
		Audience:  "http://localhost",
		IssuedAt:  1,
		NotBefore: 1,
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
	configuration.JwtKey = []byte("12345")
	configuration.HtmlFile = "./default.index.html"
	configuration.HashCost = 5
	configuration.Users = map[string]string{ globUsername: globBcrypt0000, globUsername + "H": globBcrypt1111}

	os.Exit(m.Run())
}