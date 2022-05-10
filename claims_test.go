package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidIp(t *testing.T) {
	assert := assert.New(t)

	c := claims
	ret := c.IsValidIp(globOtherIp)
	assert.False(ret)
	ret = c.IsValidIp(globValidIp)
	assert.True(ret)
}

func TestCreateJwt(t *testing.T) {
	assert := assert.New(t)
	backup := configuration.CookieName
	configuration.CookieName = "" //TODO must be "", if not panic...
	defer func() { configuration.CookieName = backup }()

	w := new(http.ResponseWriter)
	c := claims

	// errors
	err := CreateJwt(w, nil)
	assert.EqualError(err, "claims: no claims supplied")
	err = CreateJwt(nil, &c)
	assert.EqualError(err, "claims: no responsewriter supplied")

	// extend test
	err = CreateJwt(w, &c)
	assert.NoError(err)

	// created
	err = CreateJwt(w, &c)
	assert.NoError(err)
}

func TestCreateClaims(t *testing.T) {
	assert := assert.New(t)

	c := claims
	cr := credentials

	// errors
	ret, err := CreateClaims(nil, "")
	assert.EqualError(err, "claims: no credentials supplied")
	assert.Nil(ret)
	ret, err = CreateClaims(&cr, "")
	assert.EqualError(err, "claims: no ip provided")
	assert.Nil(ret)

	// created
	ret, err = CreateClaims(&cr, globValidIp)
	assert.NotEqual(*ret, c)
	assert.Equal(cr.Username, ret.Username)
	assert.Equal(globValidIp, ret.Ip)
	assert.NoError(err)
}

func TestGetClaims(t *testing.T) {
	assert := assert.New(t)

	// request errors
	ret, err := GetClaims(nil, globValidIp)
	assert.Nil(ret)
	assert.EqualError(err, "claims: invalid request")

	req, _ := http.NewRequest("POST", "http://localhost", nil)
	ret, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.EqualError(err, "http: named cookie not present")

	// jwt errors
	co := cookiesClaims["fake"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.Errorf(err, "malformed jwt")

	co = cookiesClaims["badalgo"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.EqualError(err, "claims: invalid jwt - unexpected signing method: none")

	co = cookiesClaims["altered"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.EqualError(err, "claims: invalid jwt - signature is invalid")

	co = cookiesClaims["expired"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.Errorf(err, "Expired")

	co = cookiesClaims["invalidIp"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.EqualError(err, "claims: invalid ip")

	// valid jwt
	co = cookiesClaims["valid"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, err = GetClaims(req, globValidIp)
	assert.Equal(globUsername, ret.Username)
	assert.Equal(globValidIp, ret.Ip)
	assert.Len(ret.ID, 40)
	assert.NoError(err)
}
