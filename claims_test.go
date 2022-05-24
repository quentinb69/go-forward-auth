package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func TestIsValidIp(t *testing.T) {
	assert := assert.New(t)

	c := claims["valid"]
	ret := c.IsValidIp(globOtherIp)
	assert.False(ret)
	ret = c.IsValidIp(globValidIp)
	assert.True(ret)
}

func TestCreateJwt(t *testing.T) {
	// create jwt
	refreshClaims, err := CreateClaims(&credentials, globValidIp)
	assert.NoError(t, err)
	refreshClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(configuration.TokenRefresh * time.Minute))

	// Create jwt token and sign it
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, _ := refreshToken.SignedString(configuration.JwtSecretKey)
	refreshCookie := &http.Cookie{Name: globCookieName, Value: refreshTokenString}

	testCases := []struct {
		Name                   string
		ExpectedError          bool
		ExpectedErrorContains  string
		ExpectedCookie         bool
		ExpectedCookieContains string
		Claims                 *Claims
	}{
		{
			Name:                   "CREATED",
			ExpectedError:          false,
			ExpectedErrorContains:  "",
			ExpectedCookie:         true,
			ExpectedCookieContains: "",
			Claims:                 claims["valid"],
		},
		{
			Name:                   "EXTENDED",
			ExpectedError:          false,
			ExpectedErrorContains:  "",
			ExpectedCookie:         true,
			ExpectedCookieContains: "",
			Claims:                 claims["valid"],
		},
		{
			Name:                   "INVALID_CLAIMS",
			ExpectedError:          true,
			ExpectedErrorContains:  "expired",
			ExpectedCookie:         false,
			ExpectedCookieContains: "",
			Claims:                 claims["expired"],
		},
		{
			Name:                   "MISSING_DATA_CLAIMS",
			ExpectedError:          true,
			ExpectedErrorContains:  "missing",
			ExpectedCookie:         false,
			ExpectedCookieContains: "",
			Claims:                 claims["nousername"],
		},
		{
			Name:                   "NO_CLAIMS",
			ExpectedError:          true,
			ExpectedErrorContains:  "claims: no claims supplied",
			ExpectedCookie:         false,
			ExpectedCookieContains: "",
			Claims:                 nil,
		},
	}

	for _, tc := range testCases {
		// shadow
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			// make request
			w := httptest.NewRecorder()
			wr := http.ResponseWriter(w)
			err := CreateJwt(&wr, tc.Claims)
			resp := w.Result()
			cook := resp.Cookies()

			// assert
			if tc.ExpectedError {
				assert.ErrorContains(t, err, tc.ExpectedErrorContains)
			} else {
				assert.NoError(t, err)
			}

			if tc.ExpectedCookie {
				assert.NotEmpty(t, cook)
				assert.NotEqual(t, refreshCookie, cook[len(cook)-1])
			} else {
				assert.Empty(t, cook)
			}
		})
	}

	// No response writer
	err = CreateJwt(nil, nil)
	assert.ErrorContains(t, err, "no responsewriter")
}

func TestCreateClaims(t *testing.T) {
	assert := assert.New(t)

	c := claims
	cr := credentials

	// created
	ret, err := CreateClaims(&cr, globValidIp)
	assert.NotEqual(*ret, c)
	assert.Equal(cr.Username, ret.Username)
	assert.Equal(globValidIp, ret.Ip)
	assert.NoError(err)

	// errors
	ret, err = CreateClaims(nil, "")
	assert.EqualError(err, "claims: no credentials supplied")
	assert.Nil(ret)
	ret, err = CreateClaims(&cr, "")
	assert.EqualError(err, "claims: no ip provided")
	assert.Nil(ret)
	cr.Username = "Invalid"
	ret, err = CreateClaims(&cr, "")
	assert.ErrorContains(err, "credentials")
	assert.Nil(ret)
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
	assert.ErrorContains(err, "unexpected signing method")

	co = cookiesClaims["altered"]
	req, _ = http.NewRequest("POST", "http://localhost", nil)
	req.AddCookie(co)
	ret, err = GetClaims(req, globValidIp)
	assert.Nil(ret)
	assert.ErrorContains(err, "invalid jwt")

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
