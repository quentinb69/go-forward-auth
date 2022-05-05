package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValid(t *testing.T) {
	
	// backup and restore configuration
	backup := configuration.Users
	defer func() {
		configuration.Users = backup
	  }()
	
	assert := assert.New(t)

	// No user
	configuration.Users = nil
	err := cr.IsValid()
	assert.EqualError(err, "Credentials : No user available")

	configuration.Users = map[string]string{}
	err = cr.IsValid()
	assert.EqualError(err, "Credentials : No user available")

	// bad user-password
	configuration.Users = map[string]string{"TEST2": "TOTO"}
	err = cr.IsValid()
	assert.EqualError(err, "Credentials : No password supplied for user")

	configuration.Users = map[string]string{"TEST2": "TOTO", cr.Username: ""}
	err = cr.IsValid()
	assert.EqualError(err, "Credentials : No password supplied for user")

	configuration.Users = map[string]string{"TEST2": "TOTO", cr.Username: bcrypt1111}
	err = cr.IsValid()
	assert.EqualError(err, "crypto/bcrypt: hashedPassword is not the hash of the given password")

	// valid
	configuration.Users = map[string]string{"TEST2": "TOTO", cr.Username: bcrypt0000}
	err = cr.IsValid()
	assert.NoError(err)

}

func TestGetCredentialsFromForm(t *testing.T) {
	assert := assert.New(t)
	
	// no data
	req, _ := http.NewRequest("POST", "http://localhost", nil)
	localc, err := GetCredentialsFromForm(req)
	assert.Error(err)
	assert.Nil(localc)

	// method GET
	req, _ = http.NewRequest("GET", "http://localhost?"+data, nil)
	localc, err = GetCredentialsFromForm(req)
	assert.EqualError(err, "Credentials : You must send data via POST")
	assert.Nil(localc)

	// no username
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(dataNoUsername))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	localc, err = GetCredentialsFromForm(req)
	assert.EqualError(err, "Credentials : No username found in Form")
	assert.Nil(localc)

	// no password
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(dataNoPassword))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	localc, err = GetCredentialsFromForm(req)
	assert.NoError(err)
	assert.Equal(localc.Username, username)
	assert.Equal(localc.Password, "")
	assert.Equal(localc.Action, action)
	assert.Equal(localc.Csrf, csrf)

	// valid
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	localc, err = GetCredentialsFromForm(req)
	assert.NoError(err)
	assert.Equal(localc.Username, username)
	assert.Equal(localc.Password, password)
	assert.Equal(localc.Action, action)
	assert.Equal(localc.Csrf, csrf)
}

func TestGetCredentialsFromHeader(t *testing.T) {
	assert := assert.New(t)
	req, _ := http.NewRequest("POST", "http://localhost", nil)

	// no data
	localc, err := GetCredentialsFromHeader(req)
	assert.Error(err)
	assert.Nil(localc)

	// no username
	req.Header.Set("Auth-Form", dataNoUsername)
	localc, err = GetCredentialsFromHeader(req)
	assert.EqualError(err, "Credentials : No username found in Header")
	assert.Nil(localc)

	// no password
	req.Header.Set("Auth-Form", dataNoPassword)
	localc, err = GetCredentialsFromHeader(req)
	assert.NoError(err)
	assert.Equal(localc.Username, username)
	assert.Equal(localc.Password, "")
	assert.Equal(localc.Action, action)
	assert.Equal(localc.Csrf, csrf)

	// valid
	req.Header.Set("Auth-Form", data)
	localc, err = GetCredentialsFromHeader(req)
	assert.NoError(err)
	assert.Equal(localc.Username, username)
	assert.Equal(localc.Password, password)
	assert.Equal(localc.Action, action)
	assert.Equal(localc.Csrf, csrf)
}

func TestGetCredentials(t *testing.T) {
	assert := assert.New(t)

	// GET
	req, _ := http.NewRequest("GET", "http://localhost/?"+data, nil)
	localc, err := GetCredentials(req)
	assert.EqualError(err, "Credentials : You must send data via POST")
	assert.Nil(localc)

	// POST
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	localc, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(localc.Username, username)
	assert.Equal(localc.Password, password)
	assert.Equal(localc.Action, action)
	assert.Equal(localc.Csrf, csrf)

	// HEADER
	req.Header.Set("Auth-Form", dataHeader)
	localc, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(localc.Username, username+"H")
	assert.Equal(localc.Password, passwordH)
	assert.Equal(localc.Action, action+"H")
	assert.Equal(localc.Csrf, csrf+"H")

	// POST & HEADER, valid HEADER
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Auth-Form", dataHeader)
	localc, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(localc.Username, username+"H")
	assert.Equal(localc.Password, passwordH)
	assert.Equal(localc.Action, action+"H")
	assert.Equal(localc.Csrf, csrf+"H")

	// POST & HEADER, invalid HEADER
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Auth-Form", "FAKE")
	localc, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(localc.Username, username)
	assert.Equal(localc.Password, password)
	assert.Equal(localc.Action, action)
	assert.Equal(localc.Csrf, csrf)

	// POST & HEADER, invalid HEADER and invalid POST
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader("FAKE"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Auth-Form", "FAKE")
	localc, err = GetCredentials(req)
	assert.EqualError(err, "Credentials : No username found in Form")
	assert.Nil(localc)

}
