package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

var w = new(http.ResponseWriter)

func TestIsValidIp(t *testing.T) {
	ret := c.IsValidIp(otherIp)
	assert.False(t, ret)

	ret = c.IsValidIp(validIp)
	assert.True(t, ret)
}

func TestCreateOrExtendJwt(t *testing.T) {
	assert := assert.New(t)
	localc := c
	localcr := cr

	// errors
	ret, err := CreateOrExtendJwt(w, nil, "", nil, nil)
	assert.EqualError(err, "Claims: No claims nor credential supplied")
	assert.Nil(ret)
	ret, err = CreateOrExtendJwt(nil, &localcr, "", &localc, nil)
	assert.EqualError(err, "Claims: No ResponseWriter supplied")
	assert.Nil(ret)

	// extend test
	/*ret, err = CreateOrExtendJwt(w, nil, otherIp, &localc, nil)
	assert.Equal(*ret, c)
	assert.Equal(ret.Ip, otherIp)
	assert.NoError(err)*/

	// created
	/*ret, err = CreateOrExtendJwt(w, &localcr, otherIp, nil, nil)
	assert.NotEqual(*ret, c)
	assert.Equal(ret.Username, cr.Username)
	assert.Equal(ret.Ip, otherIp)
	assert.NoError(err)*/
}

func TestGetClaims(t *testing.T) {
	assert := assert.New(t)
	req, _ := http.NewRequest("POST", "http://localhost", nil)

	// request errors
	ret, _, err := GetClaims(nil, validIp)
	assert.Nil(ret)
	assert.EqualError(err, "Claims : Invalid Request")

	ret, _, err = GetClaims(req, validIp)
	assert.Nil(ret)
	assert.EqualError(err, "http: named cookie not present")

	// jwt errors
	co := cookies["fake"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(&co)
	ret, _, err = GetClaims(req, validIp)
	assert.Nil(ret)
	assert.Errorf(err, "Malformed JWT")

	co = cookies["badAlgo"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(&co)
	ret, _, err = GetClaims(req, validIp)
	assert.Nil(ret)
	assert.EqualError(err, "Claims : Invalid Jwt - Unexpected signing method: none")

	co = cookies["altered"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(&co)
	ret, _, err = GetClaims(req, validIp)
	assert.Nil(ret)
	assert.EqualError(err, "Claims : Invalid Jwt - signature is invalid")

	co = cookies["expired"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(&co)
	ret, _, err = GetClaims(req, validIp)
	assert.Nil(ret)
	assert.Errorf(err, "Expired")

	co = cookies["invalidIp"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(&co)
	ret, _, err = GetClaims(req, otherIp)
	assert.Nil(ret)
	assert.EqualError(err, "Claims : Invalid IP")

	// valid jwt
	co = cookies["valid"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(&co)
	ret, _, err = GetClaims(req, validIp)
	assert.Equal(ret.Username, cr.Username)
	assert.Equal(ret.Ip, validIp)
	assert.NoError(err)
}
