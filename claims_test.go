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

func TestCreateOrExtendJwt(t *testing.T) {
	assert := assert.New(t)
	backup := configuration.CookieName
	configuration.CookieName = "" //TODO must be "", if not panic...
	defer func() { configuration.CookieName = backup }()

	w := new(http.ResponseWriter)
	c := claims
	cr := credentials

	// errors
	ret, err := CreateOrExtendJwt(w, nil, "", nil, nil)
	assert.EqualError(err, "Claims: No claims nor credential supplied")
	assert.Nil(ret)
	ret, err = CreateOrExtendJwt(nil, &cr, "", &c, nil)
	assert.EqualError(err, "Claims: No ResponseWriter supplied")
	assert.Nil(ret)

	// extend test
	ret, err = CreateOrExtendJwt(w, nil, globOtherIp, &c, nil)
	assert.Equal(c, *ret)
	assert.Equal(globOtherIp, ret.Ip)
	assert.NoError(err)

	// created
	ret, err = CreateOrExtendJwt(w, &cr, globOtherIp, nil, nil)
	assert.NotEqual(*ret, c)
	assert.Equal(cr.Username, ret.Username)
	assert.Equal(globOtherIp, ret.Ip)
	assert.NoError(err)
}

func TestGetClaims(t *testing.T) {
	assert := assert.New(t)

	// request errors
	req, _ := http.NewRequest("POST", "http://localhost", nil)
	ret, _, err := GetClaims(nil, globValidIp)
	assert.Nil(ret)
	assert.EqualError(err, "Claims : Invalid Request")

	req, _ = http.NewRequest("POST", "http://localhost", nil)
	ret, _, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.EqualError(err, "http: named cookie not present")

	// jwt errors
	co := cookiesClaims["fake"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, _, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.Errorf(err, "Malformed JWT")

	co = cookiesClaims["badAlgo"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, _, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.EqualError(err, "Claims : Invalid Jwt - Unexpected signing method: none")

	co = cookiesClaims["altered"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, _, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.EqualError(err, "Claims : Invalid Jwt - signature is invalid")

	co = cookiesClaims["expired"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, _, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.Errorf(err, "Expired")

	co = cookiesClaims["invalidIp"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, _, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.EqualError(err, "Claims : Invalid IP")

	// valid jwt
	co = cookiesClaims["valid"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, _, err = GetClaims(req, globValidIp)
	assert.Equal(globUsername, ret.Username)
	assert.Equal(globValidIp, ret.Ip)
	assert.NoError(err)
}
