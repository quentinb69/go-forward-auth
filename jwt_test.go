package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateClaims(t *testing.T) {
	testCases := []struct {
		name                  string
		claims                *Claims
		ip                    string
		url                   string
		expectedErrorContains string
		clearAudience         bool
		clearSubject          bool
	}{
		{"NOMINAL", TestClaims, "1.2.3.4", "url.fr", "", false, false},
		{"NOMINAL_IP_MISSING", TestClaims, "", "url.fr", "ip", false, false},
		{"NOMINAL_URL_MISSING", TestClaims, "1.2.3.4", "", "domain", false, false},
		{"BAD_URL", TestClaims, "1.2.3.4", "baddomain", "domain", false, false},
		{"NO_AUD", TestClaims, "1.2.3.4", "", "domain", true, false},
		{"NO_SUB", &Claims{}, "", "", "username", false, true},
		{"NO_CLAIMS", nil, "", "", "claims", false, false},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.clearAudience {
				tc.claims.Audience = nil
			}
			if tc.clearSubject {
				tc.claims.Subject = ""
			}
			err := ValidateClaims(tc.claims, tc.ip, tc.url)
			if tc.expectedErrorContains != "" {
				assert.ErrorContains(t, err, tc.expectedErrorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateJwtCookie(t *testing.T) {
	testCases := []struct {
		name     string
		username string
		ip       string
		domains  []string
	}{
		{"NOMINAL", "user", "1.2.3.4", []string{"url.fr"}},
		{"NOMINAL2", "admin", "1.2.3.4", []string{"toto.com"}},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cookie := CreateJwtCookie(tc.username, tc.ip, tc.domains)
			assert.NotNil(t, cookie)
			assert.Equal(t, configuration.CookieName, cookie.Name)
			assert.Equal(t, configuration.CookieDomain, cookie.Domain)
			assert.Equal(t, configuration.Tls, cookie.Secure)
			assert.Equal(t, true, cookie.HttpOnly)
		})
	}
}

func TestGetValidJwtClaims(t *testing.T) {

	// Helper to create valid cookie
	//c := CreateJwtCookie("jean", "1.2.3.4", []string{"url.net"})
	//t.Errorf("JwtToken: %+v", c.Value)
	//t.Errorf("JwtSecret: %+v", string(configuration.JwtSecretKey))

	testCases := []struct {
		name        string
		cookie      *http.Cookie
		ip          string
		url         string
		expectedNil bool
	}{
		{"NO_COOKIE", nil, "1.2.3.4", "url.net", true},
		{"NO_COOKIE2", TestCookie["empty"], "1.2.3.4", "url.net", true},
		{"NO_COOKIE3", TestCookie["fake"], "1.2.3.4", "url.net", true},
		{"EXPIRED", TestCookie["expired"], "1.2.3.4", "url.net", true},
		{"BAD_USER", TestCookie["baduser"], "1.2.3.4", "url.net", false},
		{"BAD_ALG", TestCookie["badalgo"], "1.2.3.4", "url.net", true},
		{"ALTERED", TestCookie["altered"], "1.2.3.4", "url.net", true},
		{"VALID", TestCookie["valid"], "1.2.3.4", "url.net", false},
		{"BAD_URL", TestCookie["valid"], "1.2.3.4", "test.com", true},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		co := tc.cookie
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims := GetValidJwtClaims(co, tc.ip, tc.url)
			if tc.expectedNil {
				assert.Nil(t, claims)
			} else {
				assert.NotNil(t, claims)
			}
			if claims != nil {
				assert.Equal(t, tc.ip, claims.Ip)
			}
		})
	}
}
