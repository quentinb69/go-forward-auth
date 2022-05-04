package main

import (
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
	assert.Equal(ip, expectedIp)

	expectedIp = "2.2.2.2"
	req.Header.Set("X-Forwarded-For", expectedIp+":123456, 9.9.9.9, 8.7.6.8:1235")
	ip = GetIp(req)
	assert.Equal(ip, expectedIp)

	expectedIp = "3.3.3.3"
	req.Header.Set("X-Real-IP", expectedIp)
	ip = GetIp(req)
	assert.Equal(ip, expectedIp)

	// bad ip
	req.Header.Set("X-Real-IP", " \r\n")
	ip = GetIp(req)
	expectedIp = "2.2.2.2"
	assert.Equal(ip, expectedIp)
}

func TestIsValidHash(t *testing.T) {
	cases := []struct {
		ClearText string
		ValidHash string
		IsValid   bool
	}{
		{"pass", "$2a$10$6.uxYeW/Ucxtom7yjW6Kh..oifG6IPy1ly63AjCArUKmfhu0..wtq", true},
		{"pwd", "$2a$10$/xN4OWsfJ0P8NCCKYMZa6ugsN9zgfFf9zG94RISv4hZ8eA31qLWX6", true},
		{"toto", "$2a$10$/xN4OWsfJ0P8NCCKYMZa6ugsN9zgfFf9zG94RISv4hZ8eA31q000", false},
	}
	for _, cas := range cases {
		err := IsValidHash(cas.ClearText, cas.ValidHash)
		assert.Equalf(t, (err == nil), cas.IsValid, "Error in hash validation for %s", cas.ClearText)
	}
}

func TestGetHash(t *testing.T) {
	cases := []string{"toto", "tata", "titi"}
	for _, cas := range cases {
		got, _ := GetHash(cas)
		err := IsValidHash(cas, got)
		assert.NoErrorf(t, err, "Error for %s", cas)
	}
}

func TestGenerateRand(t *testing.T) {
	cases := []uint{5, 10, 99, 0}
	for _, cas := range cases {
		n, err := GenerateRand(cas)
		if cas < 0 {
			assert.Error(t, err, "No error for %s", cas)
			continue
		}
		assert.Lenf(t, *n, int(cas), "Bad length for %s", cas)
	}

}
