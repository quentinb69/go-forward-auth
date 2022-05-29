package main

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetHost(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		header   *http.Header
		expected string
	}{
		{"URL", "valid.com", nil, "valid.com"},
		{"NONE", "", nil, ""},
		{"HEADER", "", &http.Header{"X-Forwarded-Host": []string{"valid.com"}}, "valid.com"},
		{"URL_HEADER", "invalid.com", &http.Header{"X-Forwarded-Host": []string{"valid.com"}}, "valid.com"},
	}

	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := &http.Request{
				Host: tc.url,
			}
			if tc.header != nil {
				req.Header = *tc.header
			}
			assert.Equal(t, GetHost(req), tc.expected)
		})
	}
}

func TestGetIp(t *testing.T) {
	testCases := []struct {
		Name          string
		XRealIP       string
		XForwardedFor string
		RemoteAddr    string
		ExpectedIp    string
	}{
		{
			Name:          "REAL_FORWARD_REMOTE",
			XRealIP:       "10.11.12.13:6666, 13.14.15.16",
			XForwardedFor: "1.2.3.4:8888, 4.5.6.7, 7.8.9.0:7777",
			RemoteAddr:    "20.21.22.23:5555",
			ExpectedIp:    "10.11.12.13",
		},
		{
			Name:          "FORWARD_REMOTE",
			XRealIP:       "",
			XForwardedFor: "1.2.3.4:8888, 4.5.6.7, 7.8.9.0:7777",
			RemoteAddr:    "20.21.22.23:5555",
			ExpectedIp:    "1.2.3.4",
		},
		{
			Name:          "REMOTE",
			XRealIP:       "",
			XForwardedFor: "",
			RemoteAddr:    "20.21.22.23:5555",
			ExpectedIp:    "20.21.22.23",
		},
		{
			Name:          "BAD",
			XRealIP:       "\n\r",
			XForwardedFor: "\n\r",
			RemoteAddr:    "1.2.3.4:888\n\r",
			ExpectedIp:    "1.2.3.4",
		},
		{
			Name:          "IPV6",
			XRealIP:       "\n\r",
			XForwardedFor: "\n\r",
			RemoteAddr:    "[2001:db8:0:85a3::ac1f:8001]:13516\n\r",
			ExpectedIp:    "[2001:db8:0:85a3::ac1f:8001]",
		},
		{
			Name:          "NO",
			XRealIP:       "",
			XForwardedFor: "",
			RemoteAddr:    "",
			ExpectedIp:    "",
		},
	}

	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			req, _ := http.NewRequest("POST", "http://localhost", nil)
			req.RemoteAddr = tc.RemoteAddr
			req.Header.Add("X-Forwarded-For", tc.XForwardedFor)
			req.Header.Add("X-Real-IP", tc.XRealIP)
			ip := GetIp(req)
			assert.Equal(t, tc.ExpectedIp, ip)
		})
	}
}

func TestCompareHash(t *testing.T) {
	testCases := []struct {
		Name           string
		ExpectedReturn bool
		Clear          string
		Hash           string
	}{
		{
			Name:           "VALID_ADMIN",
			ExpectedReturn: true,
			Clear:          TestAdminPassword,
			Hash:           configuration.Users["admin"].Password,
		},
		{
			Name:           "VALID_JEAN",
			ExpectedReturn: true,
			Clear:          TestJeanPassword,
			Hash:           configuration.Users["jean"].Password,
		},
		{
			Name:           "INVALID",
			ExpectedReturn: false,
			Clear:          "test",
			Hash:           configuration.Users["jean"].Password,
		},
		{
			Name:           "BAD_BCRYPT",
			ExpectedReturn: false,
			Clear:          "test",
			Hash:           "irehazulhrvuilevh",
		},
		{
			Name:           "EMPTY",
			ExpectedReturn: false,
			Clear:          "test",
			Hash:           "",
		},
	}

	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, CompareHash(tc.Hash, tc.Clear), tc.ExpectedReturn)
		})
	}
}

func TestGetHash(t *testing.T) {
	testCases := []struct {
		Name string
		Data string
	}{
		{"Test 1", "toto"},
		{"Test 2", "tata"},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			got := GetHash(tc.Data)
			assert.True(t, CompareHash(got, tc.Data))
		})
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	testCases := []uint{5, 10, 99, 0}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			t.Parallel()
			ret := GenerateRandomBytes(tc)
			assert.Len(t, *ret, int(tc))
		})
	}
}

func TestGetDomain(t *testing.T) {
	testCases := []struct {
		Url    string
		Domain string
	}{
		{"my.domain.google.com", "my.domain.google.com"},
		{"domain", "domain"},
		{"port.domain:443", "port.domain"},
		{"", ""},
		{":888", ""},
		{"[::1]:123", "[::1]"},
		{"127.0.0.1:888", "127.0.0.1"},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.Domain, GetDomain(tc.Url))
		})
	}
}

func TestCompareDomains(t *testing.T) {
	testCases := []struct {
		Domains        []string
		Url            string
		ExpectedReturn bool
	}{
		{[]string{"multiple.com", "domain.fr"}, "domain", false},
		{[]string{"single.com", "domain.fr"}, "domain.fr", true},
		{[]string{"regex1.com", ".*domain.fr"}, "domain.fr", true},
		{[]string{"regex2.com", ".*domain.fr"}, "my.domain.fr", true},
		{[]string{"regex3.com", ".*domain.fr"}, "domain.fr.nope", false},
		{[]string{"regex4.com", ".*domain.fr.*"}, "domain.fr.yep", true},
		{[]string{"long.com", "valid.domain.fr"}, "domain.fr", false},
		{[]string{"short.com", "domain.fr"}, "valid.domain.fr", true},
		{[]string{".*"}, "any.domain.fr", true},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.ExpectedReturn, CompareDomains(tc.Domains, tc.Url))
		})
	}
}
