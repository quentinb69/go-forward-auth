package main

import (
	"flag"
	"testing"
	"time"

	"github.com/knadh/koanf"
	"github.com/stretchr/testify/assert"
)

func TestValid(t *testing.T) {
	testCases := []struct {
		Name                  string
		ExpectedError         bool
		ExpectedErrorContains string
		InitializeConfig      bool
		Init                  bool
		SetTls                bool
		SetPrivateKey         string
		SetCert               string
		SetHtmlFile           string
		SetBadPort            uint
		SetJwtKey             []byte
		SetCookieName         string
		SetTokenRefresh       time.Duration
		SetTokenExpire        time.Duration
	}{
		{
			Name:             "VALID_NOINIT",
			ExpectedError:    false,
			InitializeConfig: true,
		},
		{
			Name:                  "INVALIDHTML_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "html template error",
			SetHtmlFile:           "bad_file", // not existing file
			InitializeConfig:      true,
		},
		{
			Name:                  "NOHTML_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "missing HtmlFile",
			SetHtmlFile:           "SET_EMPTY",
			InitializeConfig:      true,
		},
		{
			Name:                  "INVALIDPORT_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "bad Port",
			InitializeConfig:      true,
			SetBadPort:            100000000,
		},
		{
			Name:                  "INVALIDTLS_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "bad key pair",
			InitializeConfig:      true,
			SetTls:                true,
		},
		{
			Name:                  "INVALIDMISSINGCERT_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "bad key pair",
			InitializeConfig:      true,
			SetTls:                true,
			SetPrivateKey:         "TEST",
		},
		{
			Name:                  "INVALIDMISSINGPK_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "bad key pair",
			InitializeConfig:      true,
			SetTls:                true,
			SetCert:               "TEST",
		},
		{
			Name:                  "INVALIDKEYPAIR_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "bad key pair",
			InitializeConfig:      true,
			SetTls:                true,
			SetPrivateKey:         "TEST",
			SetCert:               "TEST",
		},
		{
			Name:                  "INVALIDJWTKEY_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "JwtKey is too small",
			InitializeConfig:      true,
			SetJwtKey:             []byte("123"),
		},
		{
			Name:                  "INVALIDCOOKIENAME_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "missing CookieName",
			InitializeConfig:      true,
			SetCookieName:         "SET_EMPTY",
		},
		{
			Name:                  "INVALIDTOKENREFRESH_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "TokenRefresh is too small",
			InitializeConfig:      true,
			SetTokenRefresh:       -1,
		},
		{
			Name:                  "INVALIDTOKENEXPIRE_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "TokenExpire is too small",
			InitializeConfig:      true,
			SetTokenExpire:        -1,
		},
		{
			Name:                  "INVALID_INIT",
			ExpectedError:         true,
			Init:                  true,
			ExpectedErrorContains: "bad key pair",
			InitializeConfig:      true,
			SetTls:                true,
		},
		{
			Name:             "VALID_INIT",
			ExpectedError:    false,
			Init:             true,
			InitializeConfig: true,
		},
	}

	for _, tc := range testCases {
		// shadow
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			c := &config{}

			// initialize with valid config
			if tc.InitializeConfig {
				c.Valid(true)
			}

			// setting vals
			switch {
			case tc.SetTls:
				c.Tls = tc.SetTls
			case tc.SetCert != "":
				c.Cert = tc.SetCert
			case tc.SetPrivateKey != "":
				c.PrivateKey = tc.SetPrivateKey
			case tc.SetBadPort != 0:
				c.Port = tc.SetBadPort
			case tc.SetHtmlFile == "SET_EMPTY": // order is important
				c.HtmlFile = ""
			case tc.SetHtmlFile != "":
				c.HtmlFile = tc.SetHtmlFile
			case len(tc.SetJwtKey) != 0:
				c.JwtKey = tc.SetJwtKey
			case len(tc.SetJwtKey) != 0:
				c.JwtKey = tc.SetJwtKey
			case tc.SetTokenExpire != 0:
				c.TokenExpire = tc.SetTokenExpire
			case tc.SetTokenRefresh != 0:
				c.TokenRefresh = tc.SetTokenRefresh
			case tc.SetCookieName == "SET_EMPTY":
				c.CookieName = ""
			case tc.SetCookieName != "":
				c.CookieName = tc.SetCookieName
			}

			err := c.Valid(tc.Init)

			if tc.ExpectedError {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.ExpectedErrorContains)
			} else {
				assert.NoError(t, err)
				assert.Len(t, c.JwtKey, 64)
				assert.NotEmpty(t, c.HtmlFile)
				assert.NotEmpty(t, c.CookieName)
				assert.GreaterOrEqual(t, c.TokenExpire, time.Duration(1))
				assert.GreaterOrEqual(t, c.TokenRefresh, time.Duration(1))
				assert.GreaterOrEqual(t, c.Port, uint(1))
				assert.LessOrEqual(t, c.Port, uint(65534))
			}
		})
	}
}

func TestLoadCommandeLine(t *testing.T) {

	// no flag
	c := &config{}
	c.LoadCommandeLine()
	assert.Empty(t, c.Debug)
	assert.Empty(t, c.ConfigurationFile)

	// inexistent flag
	if err := flag.Set("NOPE", "NOPE"); err != nil {
		assert.Error(t, err)
	}
	c.LoadCommandeLine()
	assert.Empty(t, c.Debug)
	assert.Empty(t, c.ConfigurationFile)

	// debug flag
	if err := flag.Set("d", "True"); err != nil {
		assert.NoError(t, err)
		t.FailNow() // panic if no fail
	}
	c.LoadCommandeLine()
	assert.True(t, c.Debug)
	assert.Empty(t, c.ConfigurationFile)

	// conf flag
	if err := flag.Set("conf", "test"); err != nil {
		assert.NoError(t, err)
		t.FailNow() // panic if no fail
	}
	c.LoadCommandeLine()
	assert.True(t, c.Debug)
	assert.Equal(t, "test", c.ConfigurationFile)
}

func TestLoadFile(t *testing.T) {
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
			c := &config{}
			c.ConfigurationFile = tc.File
			d, err := c.LoadFile(tc.Koanf)
			assert.Equal(t, tc.ExpectedDefault, d)
			if tc.ExpectedError {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.ExpectedErrorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLoadConfiguration(t *testing.T) {
	t.Skip()
	//TODO
	backup := configuration
	defer func() { configuration = backup }()

	newConf := &config{}
	configuration = *newConf

	// bad file
	flag.Set("conf", "./BAD_FILE")
	err := LoadGlobalConfiguration()
	assert.ErrorContains(t, err, "error loading file")
}
