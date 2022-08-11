package main

import (
	"testing"
	"time"

	flag "github.com/spf13/pflag" // POSIX compliant

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
		SetJwtSecretKey       []byte
		SetCsrfSecretKey      []byte
		SetCookieName         string
		SetTokenRefresh       time.Duration
		SetTokenExpire        time.Duration
		SetLogLevel           string
		SetMagicIp            string
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
			Name:                  "INVALIDJwtSecretKey_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "JwtSecretKey is too small",
			InitializeConfig:      true,
			SetJwtSecretKey:       []byte("123"),
		},
		{
			Name:                  "INVALIDCsrfSecretKey_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "CsrfSecretKey must be 32 bytes long",
			InitializeConfig:      true,
			SetCsrfSecretKey:      []byte("123"),
		},
		{
			Name:                  "INVALIDMAGICIP_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "MagicIp must be at least 12",
			InitializeConfig:      true,
			SetMagicIp:            "123",
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
			Name:                  "INVALIDLOLOGLEVEL_NOINIT",
			ExpectedError:         true,
			ExpectedErrorContains: "bad LogLevel",
			InitializeConfig:      true,
			SetLogLevel:           "nope",
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
		// shadow the test case to avoid modifying the test case
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			c := &Config{}

			// initialize with valid config
			if tc.InitializeConfig {
				c.Valid(true)
			}

			// setting vals
			switch {
			case tc.SetTls:
				c.Tls = tc.SetTls
			case tc.SetCert != "":
				c.Certificate = tc.SetCert
			case tc.SetPrivateKey != "":
				c.PrivateKey = tc.SetPrivateKey
			case tc.SetBadPort != 0:
				c.Port = tc.SetBadPort
			case tc.SetHtmlFile == "SET_EMPTY": // order is important
				c.HtmlFile = ""
			case tc.SetHtmlFile != "":
				c.HtmlFile = tc.SetHtmlFile
			case len(tc.SetJwtSecretKey) != 0:
				c.JwtSecretKey = tc.SetJwtSecretKey
			case len(tc.SetCsrfSecretKey) != 0:
				c.CsrfSecretKey = tc.SetCsrfSecretKey
			case tc.SetTokenExpire != 0:
				c.TokenExpire = tc.SetTokenExpire
			case tc.SetTokenRefresh != 0:
				c.TokenRefresh = tc.SetTokenRefresh
			case tc.SetCookieName == "SET_EMPTY":
				c.CookieName = ""
			case tc.SetCookieName != "":
				c.CookieName = tc.SetCookieName
			case tc.SetLogLevel != "":
				c.LogLevel = tc.SetLogLevel
			case tc.SetMagicIp != "":
				c.MagicIp = tc.SetMagicIp
			}

			err := c.Valid(tc.Init)

			if tc.ExpectedError {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.ExpectedErrorContains)
			} else {
				assert.NoError(t, err)
				assert.Len(t, c.JwtSecretKey, 64)
				assert.NotEmpty(t, c.HtmlFile)
				assert.NotEmpty(t, c.CookieName)
				assert.NotEmpty(t, c.LogLevel)
				assert.GreaterOrEqual(t, c.TokenExpire, time.Duration(1))
				assert.GreaterOrEqual(t, c.TokenRefresh, time.Duration(1))
				assert.GreaterOrEqual(t, c.Port, uint(1))
				assert.LessOrEqual(t, c.Port, uint(65534))
			}
		})
	}
}

func TestLoadCommandeLine(t *testing.T) {
	c := &Config{}
	f := flag.NewFlagSet("config", flag.ExitOnError)

	// no flag
	c.LoadCommandeLine(f)
	assert.Empty(t, c.LogLevel)
	assert.Empty(t, c.ConfigurationFile)

	// inexistent flag
	if err := f.Set("NOPE", "NOPE"); err != nil {
		assert.Error(t, err)
	}
	c.LoadCommandeLine(f)
	assert.Empty(t, c.LogLevel)
	assert.Empty(t, c.ConfigurationFile)

	// debug flag
	if err := f.Set("log", "debug"); err != nil {
		assert.NoError(t, err)
		t.FailNow() // panic if failed
	}
	c.LoadCommandeLine(f)
	assert.Equal(t, "debug", c.LogLevel)
	assert.Empty(t, c.ConfigurationFile)

	// conf flag
	if err := f.Set("config", "test"); err != nil {
		assert.NoError(t, err)
		t.FailNow() // panic if failed
	}
	c.LoadCommandeLine(f)
	assert.Equal(t, "debug", c.LogLevel)
	assert.Equal(t, []string{"test"}, c.ConfigurationFile)

	// conf hash
	if err := f.Set("hash", "pass"); err != nil {
		assert.NoError(t, err)
		t.FailNow() // panic if failed
	}
	c.LoadCommandeLine(f)
	assert.Equal(t, "debug", c.LogLevel)
	assert.Equal(t, []string{"test"}, c.ConfigurationFile)
	assert.Equal(t, "pass", c.StringToHash)
}

func TestLoadFile(t *testing.T) {
	var k = koanf.New(".")

	testCases := []struct {
		Name                  string
		ExpectedDefault       bool
		ExpectedError         bool
		ExpectedErrorContains string
		Files                 []string
		Koanf                 *koanf.Koanf
	}{
		{
			Name:                  "NOFILE",
			ExpectedDefault:       true,
			ExpectedError:         false,
			ExpectedErrorContains: "",
			Files:                 []string{},
			Koanf:                 k,
		},
		{
			Name:                  "BADFILE",
			ExpectedDefault:       false,
			ExpectedError:         true,
			ExpectedErrorContains: "open bad_file",
			Files:                 []string{"bad_file"},
			Koanf:                 k,
		},
		{
			Name:                  "NOKOANF",
			ExpectedDefault:       false,
			ExpectedError:         true,
			ExpectedErrorContains: "no koanf",
			Files:                 []string{""},
			Koanf:                 nil,
		},
		{
			Name:                  "OK",
			ExpectedDefault:       false,
			ExpectedError:         false,
			ExpectedErrorContains: "",
			Files:                 []string{"test.config.yml"},
			Koanf:                 k,
		},
		{
			Name:                  "MULTIPLE",
			ExpectedDefault:       false,
			ExpectedError:         false,
			ExpectedErrorContains: "",
			Files:                 []string{"test.config.yml", "default.config.yml"},
			Koanf:                 k,
		},
		{
			Name:                  "MULTIPLEKO",
			ExpectedDefault:       false,
			ExpectedError:         true,
			ExpectedErrorContains: "",
			Files:                 []string{"test.config.yml", "TOT"},
			Koanf:                 k,
		},
	}
	for _, tc := range testCases {
		// shadow
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			//t.Parallel()
			c := &Config{}
			c.ConfigurationFile = tc.Files
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

func TestLoad(t *testing.T) {

	testCase := []struct {
		name                  string
		flagName              string
		flagValue             string
		expectedErrorContains string
	}{
		{"bad_conf", "config", "bad_conf", "error loading file"},
		{"hash", "hash", "PASSWORD", "not an error"},
	}

	for _, tc := range testCase {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := flag.NewFlagSet(tc.name, flag.ContinueOnError)

			c := &Config{}
			k := koanf.New(".")
			c.LoadCommandeLine(f) // init
			assert.Empty(t, c.LogLevel)
			assert.Empty(t, c.ConfigurationFile)

			f.Set(tc.flagName, tc.flagValue)
			err := c.Load(k, f)
			assert.ErrorContains(t, err, tc.expectedErrorContains)
		})

	}
}
