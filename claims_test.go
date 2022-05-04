package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

var JwtKey = []byte("12345")
var w = new(http.ResponseWriter)
var c = Claims{
	Username: "TestClaims",
	Ip:       "1.2.3.4",
	StandardClaims: jwt.StandardClaims{
		ExpiresAt: 1,
		Issuer:    "toto",
		Audience:  "http://localhost",
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
	},
}
var cr = Credentials{
	Username: "Test",
	Password: "0000",
	Action:   "none",
	Csrf:     "none",
}

func TestIsValidIp(t *testing.T) {
	validIp := "1.2.3.4"
	invalidIp := "4.3.2.1"

	ret := c.IsValidIp(invalidIp)
	assert.False(t, ret)

	ret = c.IsValidIp(validIp)
	assert.True(t, ret)
}

func TestCreateOrExtendJwt(t *testing.T) {
	newIp := "9.9.9.9"
	assert := assert.New(t)

	// errors
	ret, err := CreateOrExtendJwt(w, nil, "", nil, nil)
	assert.EqualError(err, "Claims: No claims nor credential supplied")
	assert.Nil(ret)
	ret, err = CreateOrExtendJwt(nil, &cr, "", &c, nil)
	assert.EqualError(err, "Claims: No ResponseWriter supplied")
	assert.Nil(ret)

	// extend test
	ret, err = CreateOrExtendJwt(w, nil, newIp, &c, nil)
	assert.Equal(*ret, c)
	assert.Equal(ret.Ip, newIp)
	assert.NoError(err)

	// created
	ret, err = CreateOrExtendJwt(w, &cr, newIp, nil, nil)
	assert.NotEqual(*ret, c)
	assert.Equal(ret.Username, cr.Username)
	assert.Equal(ret.Ip, newIp)
	assert.NoError(err)
}

func TestGetClaims(t *testing.T) {
	configuration.JwtKey = JwtKey
	configuration.CookieName = "TEST"
	cookies := map[string]http.Cookie{
		"fake":      http.Cookie{Name: configuration.CookieName, Value: "FAKE"},
		"badAlgo":   http.Cookie{Name: configuration.CookieName, Value: "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjowLCJpYXQiOjAsImlzcyI6ImdmYSIsIm5iZiI6MH0.944b3a4a8fa6251bec89af3dba2c6eeca61e2851a13888091d9e0d3ac3af725e"},
		"altered":   http.Cookie{Name: configuration.CookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjowLCJpYXQiOjAsImlzcyI6ImdmYSIsIm5iZiI6MH0.QQoUNk38fbh31jWtuPvySLplseAZbT_rSkt4fUpxE6A"},
		"expired":   http.Cookie{Name: configuration.CookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjoxLCJpYXQiOjEsImlzcyI6ImdmYSIsIm5iZiI6MX0.NGHH08MV5QoW0mYN7M-dCeytccTkD9vTg8ZhP-jdeOI"},
		"invalidIp": http.Cookie{Name: configuration.CookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjguNS43LjUiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjAsImlzcyI6ImdmYSIsIm5iZiI6MH0.7Z18-wmkmjvQtgTJwDi7Mag4PrmuEa4oPO78M1tVEAQ"},
		"valid":     http.Cookie{Name: configuration.CookieName, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IlRlc3QiLCJJcCI6IjEuMi4zLjQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0IiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjAsImlzcyI6ImdmYSIsIm5iZiI6MH0.XWcP6GTn3AOcClc5vZMAp3D-MLNNZX1M08p5rG9RdLY"},
	}
	ip := "1.2.3.4" // in jwt valid token
	assert := assert.New(t)
	req, _ := http.NewRequest("POST", "http://localhost", nil)

	// request errors
	ret, _, err := GetClaims(nil, ip)
	assert.Nil(ret)
	assert.EqualError(err, "Claims : Invalid Request")

	ret, _, err = GetClaims(req, ip)
	assert.Nil(ret)
	assert.EqualError(err, "http: named cookie not present")

	// jwt errors
	co := cookies["fake"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(&co)
	ret, _, err = GetClaims(req, ip)
	assert.Nil(ret)
	assert.Errorf(err, "Malformed JWT")

	co = cookies["badAlgo"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(&co)
	ret, _, err = GetClaims(req, ip)
	assert.Nil(ret)
	assert.EqualError(err, "Claims : Invalid Jwt - Unexpected signing method: none")

	co = cookies["altered"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(&co)
	ret, _, err = GetClaims(req, ip)
	assert.Nil(ret)
	assert.EqualError(err, "Claims : Invalid Jwt - signature is invalid")

	co = cookies["expired"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(&co)
	ret, _, err = GetClaims(req, ip)
	assert.Nil(ret)
	assert.Errorf(err, "Expired")

	co = cookies["invalidIp"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(&co)
	ret, _, err = GetClaims(req, ip)
	assert.Nil(ret)
	assert.EqualError(err, "Claims : Invalid IP")

	// valid jwt
	co = cookies["valid"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(&co)
	ret, _, err = GetClaims(req, ip)
	assert.Equal(ret.Username, cr.Username)
	assert.Equal(ret.Ip, ip)
	assert.NoError(err)
}
