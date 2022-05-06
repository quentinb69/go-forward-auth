package main

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// get user ip
func TestGetIp(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://localhost", nil)
	assert := assert.New(t)

	// ok
	expectedIp := "1.1.1.1"
	req.RemoteAddr = expectedIp + ":123456"
	ip := GetIp(req)
	assert.Equal(expectedIp, ip)

	expectedIp = "2.2.2.2"
	req.Header.Add("X-Forwarded-For", expectedIp+":123456, 9.9.9.9, 8.7.6.8:1235")
	ip = GetIp(req)
	assert.Equal(expectedIp, ip)

	expectedIp = "3.3.3.3"
	req.Header.Add("X-Real-IP", expectedIp)
	ip = GetIp(req)
	assert.Equal(expectedIp, ip)

	// bad ip
	req.Header.Set("X-Real-IP", " \r\n")
	ip = GetIp(req)
	expectedIp = "2.2.2.2"
	assert.Equal(expectedIp, ip)
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
