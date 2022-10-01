package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetFormData(t *testing.T) {
	testCases := []struct {
		name             string
		request          http.Request
		nilFormData      bool
		expectedPassword string
		expectedUsername string
		expectedCsrf     string
		expectedAnyIp    bool
	}{
		{"NOMINAL", http.Request{Header: http.Header{"Auth-Form": []string{"password=test&username=jacques&csrf=test"}}}, false, "test", "jacques", "test", false},
		{"NO_USERNAME", http.Request{Header: http.Header{"Auth-Form": []string{"username=paul&csrf=test"}}}, true, "", "", "", false},
		{"NO_PASSWORD", http.Request{Header: http.Header{"Auth-Form": []string{"password=test&csrf=test"}}}, true, "", "", "", false},
		{"NO_OPTIONAL", http.Request{Header: http.Header{"Auth-Form": []string{"username=jean&password=test"}}}, false, "test", "jean", "", false},
		{"TOO_MUCH", http.Request{Header: http.Header{"Auth-Form": []string{"username=pierre&password=test&MOAR=TEST"}}}, true, "", "", "", false},
		{"BAD_HEADER", http.Request{Header: http.Header{"Bad-Name": []string{"username=pierre&password=test&MOAR=TEST"}}}, true, "", "", "", false},
		{"ANY_IP", http.Request{Header: http.Header{"Bad-Name": []string{"username=pierre&password=test&anyip=on&MOAR=TEST"}}}, true, "", "", "", true},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := GetFormData(&tc.request)
			if tc.nilFormData {
				assert.Nil(t, f)
			} else {
				assert.Equal(t, tc.expectedPassword, f.Password)
				assert.Equal(t, tc.expectedUsername, f.Username)
				assert.Equal(t, tc.expectedCsrf, f.Csrf)
				assert.Equal(t, tc.expectedAnyIp, f.AnyIp)
			}
		})
	}
}

func TestGenerateFormData(t *testing.T) {
	testCases := []string{"jean", "marc", ""}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc, func(t *testing.T) {
			t.Parallel()
			f := GenerateFormData(tc)
			assert.NotNil(t, f)
			assert.Equal(t, tc, f.Username)
		})
	}
}

func TestGetValidUserFromFormData(t *testing.T) {
	testCases := []struct {
		name             string
		formData         *FormData
		url              string
		nilUser          bool
		expectedUsername string
		expectedPassword string
		expectedDomains  []string
	}{
		{"NOMINAL", &FormData{Username: "admin", Password: TestAdminPassword, Csrf: "test"}, "url.com", false, "admin", configuration.Users["admin"].Password, configuration.Users["admin"].AllowedDomains},
		{"BAD_URL", &FormData{Username: "jean", Password: TestJeanPassword, Csrf: "test"}, "notallowed.net", true, "", "", nil},
		{"NO_URL", &FormData{Username: "jean", Password: TestJeanPassword, Csrf: "test"}, "", true, "", "", nil},
		// deepcode ignore HardcodedPassword/test: it's a test file
		{"NO_USERNAME", &FormData{Password: "nope", Csrf: "test"}, "", true, "", "", nil},
		{"NO_PASSWORD", &FormData{Username: "admin", Csrf: "test"}, "", true, "", "", nil},
		// deepcode ignore HardcodedPassword/test: it's a test file
		{"NOT_EXIST", &FormData{Username: "nope", Password: "test"}, "", true, "", "", nil},
		{"NO_FORMDATA", nil, "", true, "", "", nil},
	}
	for _, tc := range testCases {
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u := GetValidUserFromFormData(tc.formData, tc.url)
			if tc.nilUser {
				assert.Nil(t, u)
			} else {
				assert.NotNil(t, u)
			}
			if u != nil {
				assert.Equal(t, tc.expectedUsername, u.Username)
				assert.Equal(t, tc.expectedPassword, u.Password)
				assert.Equal(t, tc.expectedDomains, u.AllowedDomains)
			}
		})
	}

}
