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
	defer func(){ configuration.Users = backup }()

	cred := credentials

	// No user
	configuration.Users = nil
	err := cred.IsValid()
	assert.EqualError(err, "Credentials : No user available")

	configuration.Users = map[string]string{}
	err = cred.IsValid()
	assert.EqualError(err, "Credentials : No user available")

	// bad user-password
	configuration.Users = map[string]string{"TEST2": "TOTO"}
	err = cred.IsValid()
	assert.EqualError(err, "Credentials : No password supplied for user")

	configuration.Users = map[string]string{"TEST2": "TOTO", cred.Username: ""}
	err = cred.IsValid()
	assert.EqualError(err, "Credentials : No password supplied for user")

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
	assert.Error(err)
	assert.Nil(c)

	// method GET
	req, _ = http.NewRequest("GET", "http://localhost?"+globData, nil)
	c, err = GetCredentialsFromForm(req)
	assert.EqualError(err, "Credentials : You must send data via POST")
	assert.Nil(c)

	// no username
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globDataNoUsername))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentialsFromForm(req)
	assert.EqualError(err, "Credentials : No username found in Form")
	assert.Nil(c)

	// no password
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globDataNoPassword))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentialsFromForm(req)
	assert.NoError(err)
	assert.Equal(c.Username, globUsername)
	assert.Equal(c.Password, "")
	assert.Equal(c.Action, globAction)
	assert.Equal(c.Csrf, globCsrf)

	// valid
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentialsFromForm(req)
	assert.NoError(err)
	assert.Equal(c.Username, globUsername)
	assert.Equal(c.Password, globPassword)
	assert.Equal(c.Action, globAction)
	assert.Equal(c.Csrf, globCsrf)
}

func TestGetCredentialsFromHeader(t *testing.T) {
	assert := assert.New(t)

	// no data
	req, _ := http.NewRequest("POST", "http://localhost", nil)
	c, err := GetCredentialsFromHeader(req)
	assert.Error(err)
	assert.Nil(c)

	// no username
	req.Header.Set("Auth-Form", globDataNoUsername)
	c, err = GetCredentialsFromHeader(req)
	assert.EqualError(err, "Credentials : No username found in Header")
	assert.Nil(c)

	// no password
	req.Header.Set("Auth-Form", globDataNoPassword)
	c, err = GetCredentialsFromHeader(req)
	assert.NoError(err)
	assert.Equal(c.Username, globUsername)
	assert.Equal(c.Password, "")
	assert.Equal(c.Action, globAction)
	assert.Equal(c.Csrf, globCsrf)

	// valid
	req.Header.Set("Auth-Form", globData)
	c, err = GetCredentialsFromHeader(req)
	assert.NoError(err)
	assert.Equal(c.Username, globUsername)
	assert.Equal(c.Password, globPassword)
	assert.Equal(c.Action, globAction)
	assert.Equal(c.Csrf, globCsrf)
}

func TestGetCredentials(t *testing.T) {
	assert := assert.New(t)

	// GET
	req, _ := http.NewRequest("GET", "http://localhost/?"+globData, nil)
	c, err := GetCredentials(req)
	assert.EqualError(err, "Credentials : You must send data via POST")
	assert.Nil(c)

	// POST
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(c.Username, globUsername)
	assert.Equal(c.Password, globPassword)
	assert.Equal(c.Action, globAction)
	assert.Equal(c.Csrf, globCsrf)

	// HEADER
	req.Header.Set("Auth-Form", globDataHeader)
	c, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(c.Username, globUsername+"H")
	assert.Equal(c.Password, globPasswordH)
	assert.Equal(c.Action, globAction+"H")
	assert.Equal(c.Csrf, globCsrf+"H")

	// POST & HEADER, valid HEADER
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Auth-Form", globDataHeader)
	c, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(c.Username, globUsername+"H")
	assert.Equal(c.Password, globPasswordH)
	assert.Equal(c.Action, globAction+"H")
	assert.Equal(c.Csrf, globCsrf+"H")

	// POST & HEADER, invalid HEADER
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Auth-Form", "FAKE")
	c, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(c.Username, globUsername)
	assert.Equal(c.Password, globPassword)
	assert.Equal(c.Action, globAction)
	assert.Equal(c.Csrf, globCsrf)

	// POST & HEADER, invalid HEADER and invalid POST
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader("FAKE"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Auth-Form", "FAKE")
	c, err = GetCredentials(req)
	assert.EqualError(err, "Credentials : No username found in Form")
	assert.Nil(c)
}