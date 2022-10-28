package main

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

// Crypted password
// deepcode ignore HardcodedPassword/test: it's a test file
const TestAdminPassword = "pass"
const TestJeanPassword = "pwd"

var TestClaims = &Claims{
	Ip: "1.2.3.4",
	RegisteredClaims: jwt.RegisteredClaims{
		ID:        "admin",
		Issuer:    "GFA",
		Subject:   "admin",
		Audience:  []string{"url.fr"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(99 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Time{}),
		NotBefore: jwt.NewNumericDate(time.Time{}),
	},
}

// ---- valid jwt content sample ----
//
//	{
//	 "alg": "HS256",
//	 "typ": "JWT"
//	}
//
//	{
//		"Ip": "1.2.3.4",
//		"iss": "GFA",
//		"sub": "jean",
//		"aud": [
//		  "url.net"
//		],
//		"exp": 1653745215,
//		"nbf": 1653739815,
//		"iat": 1653739815,
//		"jti": "m8J8NW2xgj80nx8GcDKww0ng47F8vMY1bNk-s-J5"
//	}
var TestCookie = map[string]*http.Cookie{
	"valid":   {Name: "_test_gfa", Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJJcCI6IjEuMi4zLjQiLCJpc3MiOiJHRkEiLCJzdWIiOiJqZWFuIiwiYXVkIjpbInVybC5uZXQiXSwiZXhwIjo5OTk5OTk5OTk5LCJuYmYiOjEsImlhdCI6MSwianRpIjoibThKOE5XMnhnajgwbng4R2NES3d3MG5nNDdGOHZNWTFiTmstcy1KNSJ9.YYXMg9ag7L2N_xSBZ-a0CY7fulmGCWFUaBZLUgNgeqQ"},
	"expired": {Name: "_test_gfa", Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJJcCI6IjEuMi4zLjQiLCJpc3MiOiJHRkEiLCJzdWIiOiJqZWFuIiwiYXVkIjpbInVybC5uZXQiXSwiZXhwIjoyLCJuYmYiOjEsImlhdCI6MSwianRpIjoibThKOE5XMnhnajgwbng4R2NES3d3MG5nNDdGOHZNWTFiTmstcy1KNSJ9.WRGDh08Kr_dMj7CqaXIoflFH6jYH7lN7SFp4gOlSm3U"},
	"altered": {Name: "_test_gfa", Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJJcCI6IjEuMi4zLjQiLCJpc3MiOiJHRkEiLCJzdWIiOiJqZWFuIiwiYXVkIjpbInVybC5uZXQiXSwiZXhwIjoyLCJuYmYiOjEsImlhdCI6MSwianRpIjoibThKOE5XMnhnajgwbng4R2NES3d3MG5nNDdGOHZNWTFiTmstcy1KNSJ9.WRGDh08Kr_dMj7CqaXIoflFH6jYH7lN7SFAAAAAAAAA"},
	"badalgo": {Name: "_test_gfa", Value: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJJcCI6IjEuMi4zLjQiLCJpc3MiOiJHRkEiLCJzdWIiOiJqZWFuIiwiYXVkIjpbInVybC5uZXQiXSwiZXhwIjo5OTk5OTk5OTk5LCJuYmYiOjEsImlhdCI6MSwianRpIjoibThKOE5XMnhnajgwbng4R2NES3d3MG5nNDdGOHZNWTFiTmstcy1KNSJ9.YYXMg9ag7L2N_xSBZ-a0CY7fulmGCWFUaBZLUgNgeqQ"},
	"baduser": {Name: "_test_gfa", Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJJcCI6IjEuMi4zLjQiLCJpc3MiOiJHRkEiLCJzdWIiOiJiYWRfdXNlciIsImF1ZCI6WyJ1cmwubmV0Il0sImV4cCI6OTk5OTk5OTk5OSwibmJmIjoxLCJpYXQiOjEsImp0aSI6Im04SjhOVzJ4Z2o4MG54OEdjREt3dzBuZzQ3Rjh2TVkxYk5rLXMtSjUifQ.oYFHQvQqaqQ0C6hobmcQP4bA_DwoQx1FHqGB2EShG48"},
	"fake":    {Name: "FAKE", Value: "FAKE"},
	"empty":   {Name: "_test_gfa", Value: ""},
}

func TestMain(m *testing.M) {

	configuration = &Config{}
	configuration.ConfigurationFile = []string{"test.config.yml"}
	LoadConfigurationAndLogger()

	os.Exit(m.Run())
}

func TestLoadConfiguration(t *testing.T) {
	backup := configuration
	logbackup := log
	defer func() { configuration = backup; log = logbackup }()
	configuration = nil
	log = nil
	assert.Nil(t, configuration)
	assert.Nil(t, log)
	assert.NoError(t, LoadConfigurationAndLogger())
	configuration.ConfigurationFile = []string{"test.config.yml"}
	assert.NoError(t, LoadConfigurationAndLogger())
	assert.NotNil(t, configuration)
	assert.NotNil(t, log)
}
