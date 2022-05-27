package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetValidUser(t *testing.T) {
	var testCases = []struct {
		name         string
		username     string
		password     string
		url          string
		expecteduser *User
	}{
		{"NOMINAL", "admin", "pass", "any.url.com", configuration.Users["admin"]},
		{"NO_USERNAME", "", "pass", "any.url.com", nil},
		{"NO_PASSWORD", "admin", "", "any.url.com", nil},
		{"NO_USER", "", "", "any.url.com", nil},
		{"NO_URL", "jean", "pwd", "", nil},
		{"NOT_ALLOWED", "jean", "pwd", "forbidden.net", nil},
	}

	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			user := GetValidUser(tc.username, tc.password, tc.url)
			assert.Equal(t, tc.expecteduser, user)
			if user != nil {
				assert.Equal(t, tc.username, user.Username)
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	var testCases = []struct {
		name         string
		username     string
		expecteduser *User
	}{
		{"NOMINAL", "admin", configuration.Users["admin"]},
		{"NOMINAL", "jean", configuration.Users["jean"]},
		{"NO_USERNAME", "", nil},
		{"NO_USER", "toto", nil},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			user := GetUser(tc.username)
			assert.Equal(t, tc.expecteduser, user)
			if user != nil {
				assert.Equal(t, tc.username, user.Username)
			}
		})
	}

	backup := configuration.Users
	defer func() { configuration.Users = backup }()
	configuration.Users = nil
	assert.Nil(t, GetUser("toto"))
}

func TestAllowed(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		user     *User
		expected bool
	}{
		{"NOMINAL", "any.url.com", configuration.Users["admin"], true},
		{"NOMINAL", configuration.Users["jean"].AllowedDomains[0], configuration.Users["jean"], true},
		{"NOT_ALLOWED", "forbidden.com", configuration.Users["jean"], false},
		{"NO_URL", "", configuration.Users["jean"], false},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.user.Allowed(tc.url))
		})
	}
}
