package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func TestLoadServer(t *testing.T) {
	// missing ok test
	backup := configuration
	defer func() { configuration = backup }()
	configuration.Port = 999999
	configuration.Tls = false
	assert.Error(t, LoadServer())
	configuration.Tls = true
	assert.Error(t, LoadServer())
}

func TestToMap(t *testing.T) {
	ctx := &Context{
		FormData:  &FormData{Username: "Pierre"},
		User:      &User{Username: "Jean"},
		State:     "TestState",
		CsrfToken: "TestCsrf",
		Ip:        "TestIp",
	}

	expectedMap := map[string]interface{}{
		"username": "",
		"state":    ctx.State,
		"csrf":     ctx.CsrfToken,
		"ip":       ctx.Ip,
	}

	testCases := []struct {
		name       string
		ctx        *Context
		expected   map[string]interface{}
		noFormData bool
		noUser     bool
	}{
		{"empty", &Context{}, map[string]interface{}{"username": "", "state": "", "csrf": "", "ip": ""}, true, true},
		{"formdata", ctx, expectedMap, false, true},
		{"user", ctx, expectedMap, true, false},
		{"formdata and user", ctx, expectedMap, false, false},
	}

	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.noFormData {
				ctx.FormData = nil
			}
			if tc.noUser {
				ctx.User = nil
			}
			if tc.ctx.FormData != nil {
				assert.False(t, tc.noFormData)
				tc.expected["username"] = tc.ctx.FormData.Username
			}
			if tc.ctx.User != nil {
				assert.False(t, tc.noUser)
				tc.expected["username"] = tc.ctx.User.Username
			}
			assert.Equal(t, tc.expected, tc.ctx.ToMap())
		})
	}
}

func TestLoadTemplate(t *testing.T) {
	ctx := &Context{
		FormData:       &FormData{Username: "Pierre"},
		User:           &User{Username: "Jean"},
		State:          "",
		CsrfToken:      "TestCsrf",
		Ip:             "TestIp",
		HttpReturnCode: 123,
	}

	testCases := []struct {
		name                 string
		cookie               bool
		state                string
		expectedHttpCode     int
		expectedBodyContains string
		ctx                  *Context
	}{
		{"no_context", false, "", ctx.HttpReturnCode, "Login", nil},
		{"empty", false, "", ctx.HttpReturnCode, "", &Context{}},
		{"no_cookies_in", true, "in", ctx.HttpReturnCode, "Login", ctx},
		{"no_cookies_out", true, "out", ctx.HttpReturnCode, "Login", ctx},
		{"state_in", false, "in", ctx.HttpReturnCode, "Welcome", ctx},
	}

	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.cookie && tc.ctx != nil {
				tc.ctx.GeneratedCookie = &http.Cookie{Name: "TestCookie", Value: "TestValue"}

			}
			if tc.ctx != nil {
				tc.ctx.State = tc.state
			}
			// make request
			w := httptest.NewRecorder()
			wr := http.ResponseWriter(w)
			err := LoadTemplate(&wr, tc.ctx)
			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			// assert
			if tc.ctx != nil {
				if tc.ctx.HttpReturnCode == 0 {
					tc.ctx.HttpReturnCode = 500
				}
				assert.Equal(t, tc.ctx.HttpReturnCode, resp.StatusCode)
				assert.Contains(t, string(body), tc.expectedBodyContains)
				assert.Contains(t, string(body), tc.ctx.Ip)
				if tc.ctx.GeneratedCookie != nil && tc.ctx.User.Name != "" && tc.ctx.State == "in" {
					assert.Contains(t, string(body), tc.ctx.User.Username)
				}
			} else {
				assert.ErrorContains(t, err, "mandatory")
				assert.Empty(t, string(body))
			}
		})
	}
	assert.ErrorContains(t, LoadTemplate(nil, nil), "mandatory")
}

func TestLogoutHandler(t *testing.T) {
	testCases := []struct {
		name             string
		cookie           *http.Cookie
		expectedHttpCode int
	}{
		{"no_jwt", TestCookie["fake"], http.StatusFound},
		{"wrong_jwt", TestCookie["altered"], http.StatusFound},
		{"ok_jwt", TestCookie["valid"], http.StatusFound},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			//set request
			req := httptest.NewRequest("POST", "/logout", nil)
			req.AddCookie(tc.cookie)
			req.RemoteAddr = "1.2.3.4"

			// make request
			w := httptest.NewRecorder()
			http.HandlerFunc(LogoutHandler)(w, req)
			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			// assert
			assert.Equal(t, tc.expectedHttpCode, resp.StatusCode)
			assert.Equal(t, string(body), "")
		})
	}
}

func TestShowHomeHandler(t *testing.T) {

	// create needing refresh jwt cookies
	// OK USER
	cl := &Claims{
		Ip: "1.2.3.4",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "jean",
			ID:        base64.URLEncoding.EncodeToString([]byte("999")),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(configuration.TokenRefresh * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "GFA",
			Audience:  jwt.ClaimStrings{"url.net"},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	tokenString, _ := token.SignedString(configuration.JwtSecretKey)
	refreshCookieOk := &http.Cookie{
		Name:     configuration.CookieName,
		Value:    tokenString,
		Expires:  cl.ExpiresAt.Time,
		Domain:   configuration.CookieDomain,
		MaxAge:   int(configuration.TokenExpire * time.Minute),
		Secure:   configuration.Tls,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	// BAD USER
	cl.Subject = "bad_user"
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	tokenString, _ = token.SignedString(configuration.JwtSecretKey)
	refreshCookieBadUser := &http.Cookie{
		Name:     configuration.CookieName,
		Value:    tokenString,
		Expires:  cl.ExpiresAt.Time,
		Domain:   configuration.CookieDomain,
		MaxAge:   int(configuration.TokenExpire * time.Minute),
		Secure:   configuration.Tls,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	good_header := &http.Header{"Auth-Form": []string{"password=pass&username=admin&csrf=test&action=test"}}
	bad_header := &http.Header{"Auth-Form": []string{"password=test&username=jacques&csrf=test&action=test"}}

	testCases := []struct {
		name                 string
		cookie               *http.Cookie
		header               *http.Header
		ip                   string
		url                  string
		expectedHttpCode     int
		expectedBodyContains string
	}{
		{"no_jwt_no_cred", nil, nil, "1.2.3.4", "url.net", http.StatusUnauthorized, "Login"},
		{"bad_jwt_no_cred", TestCookie["altered"], nil, "1.2.3.4", "url.net", http.StatusUnauthorized, "Login"},
		{"bad_url_no_cred", TestCookie["altered"], nil, "1.2.3.4", "not_valid.net", http.StatusUnauthorized, "Login"},
		{"ok_jwt_no_cred", TestCookie["valid"], nil, "1.2.3.4", "url.net", http.StatusOK, "Welcome"},
		{"refresh_jwt_no_cred", refreshCookieOk, nil, "1.2.3.4", "url.net", http.StatusMultipleChoices, "Welcome"},
		{"bad_user_url_refresh_jwt_no_cred", refreshCookieBadUser, nil, "1.2.3.4", "url.net", http.StatusUnauthorized, "Login"},
		{"bad_refresh_jwt_no_cred", refreshCookieOk, nil, "1.2.3.4", "not_valid.net", http.StatusUnauthorized, "Login"},
		{"no_jwt_bad_cred", nil, bad_header, "1.2.3.4", "url.net", http.StatusUnauthorized, "Login"},
		{"no_jwt_ok_cred", nil, good_header, "1.2.3.4", "url.net", http.StatusMultipleChoices, "Login"},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			//set request
			req := httptest.NewRequest("POST", "/", nil)
			req.Host = tc.url
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}
			if tc.header != nil {
				req.Header = *tc.header
			}
			req.RemoteAddr = tc.ip

			// make request
			w := httptest.NewRecorder()
			http.HandlerFunc(ShowHomeHandler)(w, req)
			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			// assert
			assert.Equal(t, tc.expectedHttpCode, resp.StatusCode)
			assert.Contains(t, string(body), tc.expectedBodyContains)
		})
	}
}
