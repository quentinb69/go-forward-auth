package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValid(t *testing.T) {
	assert := assert.New(t)
	backup := configuration.Users
	defer func() { configuration.Users = backup }()

	cred := credentials

	// No user
	configuration.Users = nil
	err := cred.IsValid()
	assert.EqualError(err, "credentials: no user available")

	configuration.Users = map[string]string{}
	err = cred.IsValid()
	assert.EqualError(err, "credentials: no user available")

	// bad user-password
	configuration.Users = map[string]string{"TEST2": "TOTO"}
	err = cred.IsValid()
	assert.EqualError(err, "credentials: bad password supplied for user")

	configuration.Users = map[string]string{"TEST2": "TOTO", cred.Username: ""}
	err = cred.IsValid()
	assert.EqualError(err, "credentials: bad password supplied for user")

	configuration.Users = map[string]string{"TEST2": "TOTO", cred.Username: globBcrypt1111}
	err = cred.IsValid()
	assert.EqualError(err, "crypto/bcrypt: hashedPassword is not the hash of the given password")

	// valid
	configuration.Users = map[string]string{"TEST2": "TOTO", cred.Username: globBcrypt0000}
	err = cred.IsValid()
	assert.NoError(err)

}

func TestGetCredentialsFromForm(t *testing.T) {
	assert := assert.New(t)

	// no data
	req, _ := http.NewRequest("POST", "http://localhost", nil)
	c, err := GetCredentialsFromForm(req)
	assert.ErrorContains(err, "error parsing form")
	assert.Nil(c)

	// method GET
	req, _ = http.NewRequest("GET", "http://localhost?"+globData, nil)
	c, err = GetCredentialsFromForm(req)
	assert.EqualError(err, "credentials: you must send data via post")
	assert.Nil(c)

	// no username
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globDataNoUsername))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentialsFromForm(req)
	assert.ErrorContains(err, "error decoding form")
	assert.Nil(c)

	// no password
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globDataNoPassword))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentialsFromForm(req)
	assert.ErrorContains(err, "error decoding form")
	assert.Nil(c)

	// valid
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentialsFromForm(req)
	assert.NoError(err)
	assert.Equal(globUsername, c.Username)
	assert.Equal(globPassword, c.Password)
	assert.Equal(globAction, c.Action)
	assert.Equal(globCsrf, c.Csrf)
}

func TestGetCredentialsFromHeader(t *testing.T) {
	assert := assert.New(t)

	// no data
	req, _ := http.NewRequest("POST", "http://localhost", nil)
	c, err := GetCredentialsFromHeader(req)
	assert.ErrorContains(err, "error decoding header")
	assert.Nil(c)

	// no username
	req.Header = *headersCredentials["nousername"]
	c, err = GetCredentialsFromHeader(req)
	assert.ErrorContains(err, "error decoding header")
	assert.Nil(c)

	// no password
	// no username
	req.Header = *headersCredentials["nopassword"]
	c, err = GetCredentialsFromHeader(req)
	assert.ErrorContains(err, "error decoding header")
	assert.Nil(c)

	// valid
	req.Header = *headersCredentials["valid"]
	c, err = GetCredentialsFromHeader(req)
	assert.NoError(err)
	assert.Equal(globUsername, c.Username)
	assert.Equal(globPassword, c.Password)
	assert.Equal(globAction, c.Action)
	assert.Equal(globCsrf, c.Csrf)
}

func TestGetCredentials(t *testing.T) {
	assert := assert.New(t)

	// GET
	req, _ := http.NewRequest("GET", "http://localhost/?"+globData, nil)
	c, err := GetCredentials(req)
	assert.EqualError(err, "credentials: you must send data via post")
	assert.Nil(c)

	// POST
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globData))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(globUsername, c.Username)
	assert.Equal(globPassword, c.Password)
	assert.Equal(globAction, c.Action)
	assert.Equal(globCsrf, c.Csrf)

	// HEADER
	req.Header = *headersCredentials["validH"]
	c, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(globUsername+"H", c.Username)
	assert.Equal(globPasswordH, c.Password)
	assert.Equal(globAction+"H", c.Action)
	assert.Equal(globCsrf+"H", c.Csrf)

	// POST & HEADER, valid HEADER
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globData))
	req.Header = *headersCredentials["validH"]
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(globUsername+"H", c.Username)
	assert.Equal(globPasswordH, c.Password)
	assert.Equal(globAction+"H", c.Action)
	assert.Equal(globCsrf+"H", c.Csrf)

	// POST & HEADER, invalid HEADER
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globData))
	req.Header = *headersCredentials["fake"]
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(globUsername, c.Username)
	assert.Equal(globPassword, c.Password)
	assert.Equal(globAction, c.Action)
	assert.Equal(globCsrf, c.Csrf)

	// POST & HEADER, invalid HEADER and invalid POST
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader("FAKE"))
	req.Header = *headersCredentials["fake"]
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentials(req)
	assert.ErrorContains(err, "credentials: error decoding form")
	assert.Nil(c)
}
