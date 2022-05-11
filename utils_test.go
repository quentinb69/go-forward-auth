package main

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// get user ip
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
		// shadow
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

func TestIsValidHash(t *testing.T) {
	testCases := []struct {
		Name           string
		ExpectedReturn bool
		Clear          string
		Hash           string
	}{
		{
			Name:           "valid",
			ExpectedReturn: true,
			Clear:          globPassword,
			Hash:           globBcrypt0000,
		},
		{
			Name:           "validH",
			ExpectedReturn: true,
			Clear:          globPasswordH,
			Hash:           globBcrypt1111,
		},
		{
			Name:           "invalid",
			ExpectedReturn: false,
			Clear:          "test",
			Hash:           globBcrypt0000,
		},
	}

	for _, tc := range testCases {
		// shadow
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			err := IsValidHash(tc.Clear, tc.Hash)
			assert.Equal(t, (err == nil), tc.ExpectedReturn)
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
		// shadow
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			got, _ := GetHash(tc.Data)
			err := IsValidHash(tc.Data, got)
			assert.NoError(t, err)
		})
	}
}

func TestGenerateRand(t *testing.T) {
	testCases := []uint{5, 10, 99, 0}
	for _, tc := range testCases {
		// shadow
		tc := tc
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			t.Parallel()
			ret, _ := GenerateRand(tc)
			assert.Len(t, *ret, int(tc))
		})
	}
}
