package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

type structTestHandler struct {
	Name                 string
	ExpectedHttpCode     int
	ExpectedBodyContains string
	Ip                   string
	Header               http.Header
	Cookie               http.Cookie
}

func TestRenderTemplate(t *testing.T) {

	testCases := []struct {
		Name                 string
		ExpectedHttpCode     int
		ExpectedBodyContains string
		Claims               *Claims
		Ip                   string
		State                string
	}{
		{
			Name:                 "IN_NOCLAIMS",
			ExpectedHttpCode:     999,
			ExpectedBodyContains: "Welcome",
			Claims:               nil,
			Ip:                   globValidIp,
			State:                "in",
		},
		{
			Name:                 "OUT_NOCLAIMS",
			ExpectedHttpCode:     123,
			ExpectedBodyContains: "Login</",
			Claims:               nil,
			Ip:                   globValidIp,
			State:                "out",
		},
		{
			Name:                 "IN_CLAIMS",
			ExpectedHttpCode:     789,
			ExpectedBodyContains: "Welcome",
			Claims:               claims["valid"],
			Ip:                   globValidIp,
			State:                "in",
		},
		{
			Name:                 "OUT_CLAIMS",
			ExpectedHttpCode:     107,
			ExpectedBodyContains: "Login</",
			Claims:               claims["valid"],
			Ip:                   globValidIp,
			State:                "out",
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
			RenderTemplate(&wr, tc.Claims, tc.Ip, tc.ExpectedHttpCode, tc.State)
			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			// assert
			assert.Equal(t, tc.ExpectedHttpCode, resp.StatusCode)
			assert.Contains(t, string(body), tc.ExpectedBodyContains)
			assert.Contains(t, string(body), tc.Ip)
			if tc.Claims != nil && tc.Claims.Username != "" && tc.State == "in" {
				assert.Contains(t, string(body), tc.Claims.Username)
			}
		})
	}

	err := RenderTemplate(nil, nil, "", 0, "")
	assert.ErrorContains(t, err, "responsewriter is mandatory")
}

func TestLogout(t *testing.T) {
	testCases := []structTestHandler{
		{
			Name:                 "NOJWT_NOCREDS",
			ExpectedHttpCode:     401,
			ExpectedBodyContains: "",
			Ip:                   globValidIp,
			Header:               http.Header{},
			Cookie:               http.Cookie{},
		},
		{
			Name:                 "BADJWT_NOCREDS",
			ExpectedHttpCode:     401,
			ExpectedBodyContains: "",
			Ip:                   globValidIp,
			Header:               http.Header{},
			Cookie:               *cookiesClaims["altered"],
		},
		{
			Name:                 "OKJWT_NOCREDS",
			ExpectedHttpCode:     302,
			ExpectedBodyContains: "",
			Ip:                   globValidIp,
			Header:               http.Header{},
			Cookie:               *cookiesClaims["valid"],
		},
	}

	for _, tc := range testCases {
		// shadow
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			//set request
			req := httptest.NewRequest("POST", "/logout", nil)
			req.Header = tc.Header
			req.AddCookie(&tc.Cookie)
			req.RemoteAddr = tc.Ip

			// make request
			w := httptest.NewRecorder()
			http.HandlerFunc(Logout)(w, req)
			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			// assert
			assert.Equal(t, tc.ExpectedHttpCode, resp.StatusCode)
			assert.Contains(t, string(body), tc.ExpectedBodyContains)
		})
	}
}

func TestHome(t *testing.T) {
	// create jwt
	refreshClaims, err := CreateClaims(&credentials, globValidIp)
	assert.NoError(t, err)
	refreshClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(configuration.TokenRefresh * time.Minute))

	// Create jwt token and sign it
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, _ := refreshToken.SignedString(configuration.JwtKey)
	refreshCookie := &http.Cookie{Name: globCookieName, Value: refreshTokenString}

	testCases := []structTestHandler{
		{
			Name:                 "NOJWT_NOCREDS",
			ExpectedHttpCode:     401,
			ExpectedBodyContains: "Login</button",
			Ip:                   globValidIp,
			Header:               http.Header{},
			Cookie:               http.Cookie{},
		},
		{
			Name:                 "BADJWT_NOCREDS",
			ExpectedHttpCode:     401,
			ExpectedBodyContains: "Login</button",
			Ip:                   globValidIp,
			Header:               http.Header{},
			Cookie:               *cookiesClaims["altered"],
		},
		{
			Name:                 "NOJWT_BADCREDS",
			ExpectedHttpCode:     401,
			ExpectedBodyContains: "Login</button",
			Ip:                   globValidIp,
			Header:               *headersCredentials["invalid"],
			Cookie:               http.Cookie{},
		},
		{
			Name:                 "BADJWT_BADCREDS",
			ExpectedHttpCode:     401,
			ExpectedBodyContains: "Login</button",
			Ip:                   globValidIp,
			Header:               *headersCredentials["invalid"],
			Cookie:               *cookiesClaims["altered"],
		},
		{
			Name:                 "BADJWT_OKCREDS",
			ExpectedHttpCode:     300,
			ExpectedBodyContains: "Welcome",
			Ip:                   globValidIp,
			Header:               *headersCredentials["valid"],
			Cookie:               *cookiesClaims["altered"],
		},
		{
			Name:                 "REFRESHJWT_NOCREDS",
			ExpectedHttpCode:     300,
			ExpectedBodyContains: "Welcome",
			Ip:                   globValidIp,
			Header:               http.Header{},
			Cookie:               *refreshCookie,
		},
		{
			Name:                 "OKJWT_NOCREDS",
			ExpectedHttpCode:     200,
			ExpectedBodyContains: "Welcome",
			Ip:                   globValidIp,
			Header:               http.Header{},
			Cookie:               *cookiesClaims["valid"],
		},
	}

	for _, tc := range testCases {
		// shadow
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			//set request
			req := httptest.NewRequest("POST", "/home", nil)
			req.Header = tc.Header
			req.AddCookie(&tc.Cookie)
			req.RemoteAddr = tc.Ip

			// make request
			w := httptest.NewRecorder()
			http.HandlerFunc(Home)(w, req)
			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			// assert
			assert.Equal(t, tc.ExpectedHttpCode, resp.StatusCode)
			assert.Contains(t, string(body), tc.ExpectedBodyContains)
		})
	}
}
