package main

import (
	"testing"
	"time"

	"github.com/knadh/koanf"
	"github.com/stretchr/testify/assert"
)

func TestSetValid(t *testing.T) {
	con := &config{}
	err := con.setValid()
	assert.NoError(t, err)

	con.HtmlFile = "bad_file"
	err = con.setValid()
	assert.ErrorContains(t, err, "html template error")

	con.HtmlFile = "main.go"
	err = con.setValid()
	assert.NoError(t, err)
	assert.Len(t, con.JwtKey, 64)
	assert.NotEmpty(t, con.HtmlFile)
	assert.NotEmpty(t, con.CookieName)
	assert.GreaterOrEqual(t, con.TokenExpire, time.Duration(1))
	assert.GreaterOrEqual(t, con.TokenRefresh, time.Duration(1))
	assert.GreaterOrEqual(t, con.Port, uint(1))
	assert.LessOrEqual(t, con.Port, uint(65534))

	con.Tls = true
	err = con.setValid()
	assert.ErrorContains(t, err, "please provide")

	con.PrivateKey = "TEST"
	err = con.setValid()
	assert.ErrorContains(t, err, "please provide")

	con.Cert = "TEST"
	err = con.setValid()
	assert.ErrorContains(t, err, "bad key pair")
}

func TestLoadCommandeLineConfiguration(t *testing.T) {

}

func TestLoadFileConfiguration(t *testing.T) {
	var k = koanf.New(".")
	testCases := []struct {
		Name                  string
		ExpectedDefault       bool
		ExpectedError         bool
		ExpectedErrorContains string
		File                  string
		Koanf                 *koanf.Koanf
	}{
		{
			Name:                  "NOFILE",
			ExpectedDefault:       true,
			ExpectedError:         false,
			ExpectedErrorContains: "",
			File:                  "",
			Koanf:                 k,
		},
		{
			Name:                  "BADFILE",
			ExpectedDefault:       false,
			ExpectedError:         true,
			ExpectedErrorContains: "open bad_file",
			File:                  "bad_file",
			Koanf:                 k,
		},
		{
			Name:                  "NOKOANF",
			ExpectedDefault:       false,
			ExpectedError:         true,
			ExpectedErrorContains: "no koanf",
			File:                  "",
			Koanf:                 nil,
		},
	}
	for _, tc := range testCases {
		// shadow
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			configuration.ConfigurationFile = tc.File
			d, err := LoadFileConfiguration(tc.Koanf)
			assert.Equal(t, tc.ExpectedDefault, d)
			if tc.ExpectedError {
				assert.ErrorContains(t, err, tc.ExpectedErrorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLoadConfiguration(t *testing.T) {

}
