package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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

	//TODO test rendering
	t.Skip()

	assert := assert.New(t)
	w := new(http.ResponseWriter)
	c := claims
	code := 999

	// state in and claims
	RenderTemplate(w, &c, globValidIp, code, "in")
	assert.Equal(999, w)

	// state in No claims
	RenderTemplate(w, &c, globValidIp, code, "in")
	assert.Equal(999, w)

	// state out
	RenderTemplate(w, &c, globValidIp, code, "out")
	assert.Equal(999, w)
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
	//TODO test extend jwt test
	testCases := []structTestHandler{
		{
			Name:                 "NOJWT_NOCREDS",
			ExpectedHttpCode:     401,
			ExpectedBodyContains: "Login",
			Ip:                   globValidIp,
			Header:               http.Header{},
			Cookie:               http.Cookie{},
		},
		{
			Name:                 "BADJWT_NOCREDS",
			ExpectedHttpCode:     401,
			ExpectedBodyContains: "Login",
			Ip:                   globValidIp,
			Header:               http.Header{},
			Cookie:               *cookiesClaims["altered"],
		},
		{
			Name:                 "NOJWT_BADCREDS",
			ExpectedHttpCode:     401,
			ExpectedBodyContains: "Login",
			Ip:                   globValidIp,
			Header:               *headersCredentials["invalid"],
			Cookie:               http.Cookie{},
		},
		{
			Name:                 "BADJWT_BADCREDS",
			ExpectedHttpCode:     401,
			ExpectedBodyContains: "Login",
			Ip:                   globValidIp,
			Header:               *headersCredentials["invalid"],
			Cookie:               *cookiesClaims["altered"],
		},
		{
			Name:                 "BADJWT_OKCREDS",
			ExpectedHttpCode:     300,
			ExpectedBodyContains: "Login",
			Ip:                   globValidIp,
			Header:               *headersCredentials["valid"],
			Cookie:               *cookiesClaims["altered"],
		},
		{
			Name:                 "OKJWT_NOCREDS",
			ExpectedHttpCode:     200,
			ExpectedBodyContains: "Login",
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
