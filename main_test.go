package main

import (
	"testing"
	"time"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v4"
)


// Crypted password
const bcrypt0000 = "$2a$05$5Q7AIdXjMaiCnd2VZYNlke7PskIgXNaaOKrUVIa787VUU5L5usooG"
const bcrypt1111 = "$2a$05$JQKwvqAyG1SzDEr.jkp3Ke1YEDwt1XVkrvjG/0bj5eb8o9CHX0VWi"

// Ip
const validIp = "1.2.3.4" // valid in jwt
const otherIp = "4.3.2.1" // invalid in jwt

// Form and Header data
const username = "Test"
const password = "0000"
const passwordH = "1111" // for header
const action = "none"
const csrf = "none"
const dataNoUsername = "action=" + action + "&csrf=" + csrf
const dataNoPassword = "username=" + username + "&action=" + action + "&csrf=" + csrf
const data = "username=" + username + "&password=" + password + "&action=" + action + "&csrf=" + csrf
const dataHeader = "username=" + username + "H&password=" + passwordH + "&action=" + action + "H&csrf=" + csrf + "H"

// Structs
var cookies = map[string]http.Cookie{}	
var c = Claims{}
var cr = Credentials{}

func TestMain(m *testing.M) {
	configuration.Tls = false
	configuration.Port = 80
	configuration.CookieName = "Test"
	configuration.CookieDomain = "localhost"
	configuration.TokenExpire = 10
	configuration.JwtKey = []byte("12345")
	configuration.HtmlFile = "./default.index.html"
	configuration.HashCost = 5
	configuration.Users = map[string]string{username: bcrypt0000, username + "H": bcrypt1111}
	
	cr = Credentials{
		Username: username,
		Password: password,
		Action:   action,
		Csrf:     csrf,
	}

	c = Claims{
		Username: username,
		Ip:       validIp,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: 9999999999,
			Issuer:    "FAKE",
			Audience:  "http://localhost",
			IssuedAt:  time.Now().Unix(),
			NotBefore: time.Now().Unix(),
		},
	}

	cookies = map[string]http.Cookie{
		"fake":      http.Cookie{Name: configuration.CookieName, Value: "FAKE"},
		"badAlgo":   http.Cookie{Name: configuration.CookieName, Value: "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjowLCJpYXQiOjAsImlzcyI6ImdmYSIsIm5iZiI6MH0.944b3a4a8fa6251bec89af3dba2c6eeca61e2851a13888091d9e0d3ac3af725e"},
		"altered":   http.Cookie{Name: configuration.CookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjowLCJpYXQiOjAsImlzcyI6ImdmYSIsIm5iZiI6MH0.QQoUNk38fbh31jWtuPvySLplseAZbT_rSkt4fUpxE6A"},
		"expired":   http.Cookie{Name: configuration.CookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjoxLCJpYXQiOjEsImlzcyI6ImdmYSIsIm5iZiI6MX0.NGHH08MV5QoW0mYN7M-dCeytccTkD9vTg8ZhP-jdeOI"},
		"invalidIp": http.Cookie{Name: configuration.CookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjguNS43LjUiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjAsImlzcyI6ImdmYSIsIm5iZiI6MH0.7Z18-wmkmjvQtgTJwDi7Mag4PrmuEa4oPO78M1tVEAQ"},
		"valid":     http.Cookie{Name: configuration.CookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjAsImlzcyI6ImdmYSIsIm5iZiI6MH0.XWcP6GTn3AOcClc5vZMAp3D-MLNNZX1M08p5rG9RdLY"},
	}

	os.Exit(m.Run())
}