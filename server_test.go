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
	configuration.PrivateKey = "BAD KEY"
	assert.Error(t, LoadServer())
	// autogenerate key
	configuration.PrivateKey = ""
	assert.Error(t, LoadServer())
}

func TestGetUsername(t *testing.T) {
	u := &User{Username: "User"}
	c := &Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "Claims"}}
	f := &FormData{Username: "FormData"}

	testCases := []struct {
		name             string
		setUser          bool
		setClaims        bool
		setFormdata      bool
		expectedUsername string
	}{
		{"ALL", true, true, true, "User"},
		{"USER", true, false, false, "User"},
		{"CLAIMS", false, true, false, "Claims"},
		{"FORMDATA", false, false, true, "FormData"},
		{"NONE", false, false, false, ""},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			//set request
			ctx := &Context{}
			if tc.setUser {
				ctx.User = u
			}
			if tc.setClaims {
				ctx.Claims = c
			}
			if tc.setFormdata {
				ctx.FormData = f
			}
			assert.Equal(t, tc.expectedUsername, ctx.GetUsername())
		})
	}
}

func TestToMap(t *testing.T) {
	ctx := &Context{
		FormData:     &FormData{Username: "Pierre"},
		User:         &User{Username: "Jean"},
		State:        "TestState",
		CsrfToken:    "TestCsrf",
		Ip:           "TestIp",
		ErrorMessage: "TestError",
	}

	expectedMap := map[string]interface{}{
		"username": "",
		"state":    ctx.State,
		"csrf":     ctx.CsrfToken,
		"ip":       ctx.Ip,
		"error":    ctx.ErrorMessage,
	}

	testCases := []struct {
		name       string
		ctx        *Context
		expected   map[string]interface{}
		noFormData bool
		noUser     bool
	}{
		{"empty", &Context{}, map[string]interface{}{"username": "", "state": "", "csrf": "", "ip": "", "error": ""}, true, true},
		{"formdata", ctx, expectedMap, false, true},
		{"user", ctx, expectedMap, true, false},
		{"formdata and user", ctx, expectedMap, false, false},
	}

	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			//t.Parallel()
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
			//t.Parallel()
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
					tc.ctx.HttpReturnCode = http.StatusNotImplemented
				}
				assert.Equal(t, tc.ctx.HttpReturnCode, resp.StatusCode)
				assert.Contains(t, string(body), tc.expectedBodyContains)
				assert.Contains(t, string(body), tc.ctx.Ip)
				if tc.ctx.GeneratedCookie != nil {
					cook := resp.Cookies()
					assert.NotNil(t, cook)
					if assert.NotNil(t, cook[0]) {
						assert.Equal(t, tc.ctx.GeneratedCookie.Name, cook[0].Name)
						assert.Equal(t, tc.ctx.GeneratedCookie.Value, cook[0].Value)
					}
				}
				if tc.ctx.State == "in" {
					assert.Equal(t, tc.ctx.GetUsername(), resp.Header.Get("Remote-User"))
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
			Audience:  jwt.ClaimStrings{".*"},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	tokenString, _ := token.SignedString([]byte(configuration.JwtSecretKey))
	refreshCookieOk := &http.Cookie{
		Name:     configuration.CookieName,
		Value:    tokenString,
		Expires:  cl.ExpiresAt.Time,
		Domain:   configuration.CookieDomain,
		MaxAge:   int(configuration.TokenExpire * time.Minute),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	// BAD USER
	cl.Subject = "bad_user"
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	tokenString, _ = token.SignedString([]byte(configuration.JwtSecretKey))
	refreshCookieBadUser := &http.Cookie{
		Name:     configuration.CookieName,
		Value:    tokenString,
		Expires:  cl.ExpiresAt.Time,
		Domain:   configuration.CookieDomain,
		MaxAge:   int(configuration.TokenExpire * time.Minute),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	good_header := &http.Header{"Auth-Form": []string{"password=pass&username=admin&csrf=test"}}
	bad_header := &http.Header{"Auth-Form": []string{"password=test&username=jacques&csrf=test"}}

	testCases := []struct {
		name                  string
		cookie                *http.Cookie
		header                *http.Header
		ip                    string
		url                   string
		expectedHttpCode      int
		expectedBodyContains  string
		expectedConnectCookie bool
		expectedRemoveCookie  bool
		forwardurl            bool
	}{
		{"no_jwt_no_cred", nil, nil, "1.2.3.4", "url.net", http.StatusUnauthorized, "Login", false, false, false},
		{"bad_jwt_no_cred", TestCookie["altered"], nil, "1.2.3.4", "url.net", http.StatusForbidden, "Login", false, false, false},
		{"bad_url_no_cred", TestCookie["valid"], nil, "1.2.3.4", "not_valid.net", http.StatusForbidden, "Login", false, false, false},
		{"ok_jwt_no_cred", TestCookie["valid"], nil, "1.2.3.4", "url.net", http.StatusOK, "Welcome", false, false, false},
		{"refresh_jwt_no_cred", refreshCookieOk, nil, "1.2.3.4", "url.net", http.StatusMultipleChoices, "Welcome", true, false, false},
		{"bad_url_refresh_jwt_no_cred", refreshCookieOk, nil, "1.2.3.4", "other.url.net.bad", http.StatusMultipleChoices, "Login", false, true, false},
		{"bad_user_refresh_jwt_no_cred", refreshCookieBadUser, nil, "1.2.3.4", "not_valid.net", http.StatusForbidden, "Login", false, true, false},
		{"no_jwt_bad_cred", nil, bad_header, "1.2.3.4", "url.net", http.StatusUnauthorized, "Login", false, false, false},
		{"no_jwt_ok_cred", nil, good_header, "1.2.3.4", "url.net", http.StatusMultipleChoices, "Login", true, false, false},

		{"FWD_no_jwt_no_cred", nil, nil, "1.2.3.4", "url.net", http.StatusUnauthorized, "Login", false, false, true},
		{"FWD_bad_jwt_no_cred", TestCookie["altered"], nil, "1.2.3.4", "url.net", http.StatusForbidden, "Login", false, false, true},
		{"FWD_bad_url_no_cred", TestCookie["valid"], nil, "1.2.3.4", "not_valid.net", http.StatusForbidden, "Login", false, false, true},
		{"FWD_ok_jwt_no_cred", TestCookie["valid"], nil, "1.2.3.4", "url.net", http.StatusOK, "Welcome", false, false, true},
		{"FWD_refresh_jwt_no_cred", refreshCookieOk, nil, "1.2.3.4", "url.net", http.StatusMultipleChoices, "Welcome", true, false, true},
		{"FWD_bad_url_refresh_jwt_no_cred", refreshCookieOk, nil, "1.2.3.4", "other.url.net.bad", http.StatusMultipleChoices, "Login", false, true, true},
		{"FWD_bad_user_refresh_jwt_no_cred", refreshCookieBadUser, nil, "1.2.3.4", "not_valid.net", http.StatusForbidden, "Login", false, true, true},
		{"FWD_no_jwt_bad_cred", nil, bad_header, "1.2.3.4", "url.net", http.StatusUnauthorized, "Login", false, false, true},
		{"FWD_no_jwt_ok_cred", nil, good_header, "1.2.3.4", "url.net", http.StatusMultipleChoices, "Login", true, false, true},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			//set request
			req := httptest.NewRequest("POST", "/", nil)

			// set url
			if tc.forwardurl {
				req.Host = "auth:443"
				req.Header.Add("X-Forwarded-Host", tc.url)
			} else {
				req.Host = tc.url
			}

			// set cookie
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}

			// set crendentials
			if tc.header != nil {
				req.Header = *tc.header
			}

			// set ip
			req.RemoteAddr = tc.ip

			// make request
			w := httptest.NewRecorder()
			http.HandlerFunc(ShowHomeHandler)(w, req)
			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			// assert
			assert.Equal(t, tc.expectedHttpCode, resp.StatusCode)
			assert.Contains(t, string(body), tc.expectedBodyContains)
			if tc.expectedConnectCookie {
				assert.Len(t, resp.Cookies(), 1)
			}
			if tc.expectedRemoveCookie {
				assert.Len(t, resp.Cookies(), 1)
			}
			if !tc.expectedRemoveCookie && !tc.expectedConnectCookie {
				assert.Len(t, resp.Cookies(), 0)
			}
		})
	}
}

func TestHealthHandler(t *testing.T) {
	// make request
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	http.HandlerFunc(HealthHandler)(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assert.Contains(t, string(body), "OK")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
