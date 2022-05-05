package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var cred = Credentials{
	Username: "Test",
	Password: "0000",
	Action:   "none",
	Csrf:     "none",
}

const bcrypt0000 = "$2a$05$5Q7AIdXjMaiCnd2VZYNlke7PskIgXNaaOKrUVIa787VUU5L5usooG"
const bcrypt1111 = "$2a$05$JQKwvqAyG1SzDEr.jkp3Ke1YEDwt1XVkrvjG/0bj5eb8o9CHX0VWi"

func TestIsValid(t *testing.T) {
	assert := assert.New(t)

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

	configuration.Users = map[string]string{"TEST2": "TOTO", cred.Username: bcrypt1111}
	err = cred.IsValid()
	assert.EqualError(err, "crypto/bcrypt: hashedPassword is not the hash of the given password")

	// valid
	configuration.Users = map[string]string{"TEST2": "TOTO", cred.Username: bcrypt0000}
	err = cred.IsValid()
	assert.NoError(err)

}

func TestGetCredentialsFromForm(t *testing.T) {
	assert := assert.New(t)
	username := "user"
	password := "pass"
	action := "act"
	csrf := "cs"
	dataNoUsername := "action=" + action + "&csrf=" + csrf
	dataNoPassword := "username=" + username + "&action=" + action + "&csrf=" + csrf
	data := "username=" + username + "&password=" + password + "&action=" + action + "&csrf=" + csrf

	// no data
	req, _ := http.NewRequest("POST", "http://localhost", nil)
	c, err := GetCredentialsFromForm(req)
	assert.Error(err)
	assert.Nil(c)

	// method GET
	req, _ = http.NewRequest("GET", "http://localhost?"+data, nil)
	c, err = GetCredentialsFromForm(req)
	assert.EqualError(err, "Credentials : You must send data via POST")
	assert.Nil(c)

	// no username
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(dataNoUsername))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentialsFromForm(req)
	assert.EqualError(err, "Credentials : No username found in Form")
	assert.Nil(c)

	// no password
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(dataNoPassword))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentialsFromForm(req)
	assert.NoError(err)
	assert.Equal(c.Username, username)
	assert.Equal(c.Password, "")
	assert.Equal(c.Action, action)
	assert.Equal(c.Csrf, csrf)

	// valid
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentialsFromForm(req)
	assert.NoError(err)
	assert.Equal(c.Username, username)
	assert.Equal(c.Password, password)
	assert.Equal(c.Action, action)
	assert.Equal(c.Csrf, csrf)
}

func TestGetCredentialsFromHeader(t *testing.T) {
	assert := assert.New(t)
	username := "user"
	password := "pass"
	action := "act"
	csrf := "cs"
	dataNoUsername := "action=" + action + "&csrf=" + csrf
	dataNoPassword := "username=" + username + "&action=" + action + "&csrf=" + csrf
	data := "username=" + username + "&password=" + password + "&action=" + action + "&csrf=" + csrf
	req, _ := http.NewRequest("POST", "http://localhost", nil)

	// no data
	c, err := GetCredentialsFromHeader(req)
	assert.Error(err)
	assert.Nil(c)

	// no username
	req.Header.Set("Auth-Form", dataNoUsername)
	c, err = GetCredentialsFromHeader(req)
	assert.EqualError(err, "Credentials : No username found in Header")
	assert.Nil(c)

	// no password
	req.Header.Set("Auth-Form", dataNoPassword)
	c, err = GetCredentialsFromHeader(req)
	assert.NoError(err)
	assert.Equal(c.Username, username)
	assert.Equal(c.Password, "")
	assert.Equal(c.Action, action)
	assert.Equal(c.Csrf, csrf)

	// valid
	req.Header.Set("Auth-Form", data)
	c, err = GetCredentialsFromHeader(req)
	assert.NoError(err)
	assert.Equal(c.Username, username)
	assert.Equal(c.Password, password)
	assert.Equal(c.Action, action)
	assert.Equal(c.Csrf, csrf)
}

func TestGetCredentials(t *testing.T) {
	assert := assert.New(t)
	username := cred.Username
	password := cred.Password
	passwordH := "1111"
	action := "act"
	csrf := "cs"
	data := "username=" + username + "&password=" + password + "&action=" + action + "&csrf=" + csrf
	dataHeader := "username=" + username + "H&password=" + passwordH + "&action=" + action + "H&csrf=" + csrf + "H"

	configuration.Users = map[string]string{username: bcrypt0000, username + "H": bcrypt1111}

	// GET
	req, _ := http.NewRequest("GET", "http://localhost/?"+data, nil)
	c, err := GetCredentials(req)
	assert.EqualError(err, "Credentials : You must send data via POST")
	assert.Nil(c)

	// POST
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(c.Username, username)
	assert.Equal(c.Password, password)
	assert.Equal(c.Action, action)
	assert.Equal(c.Csrf, csrf)

	// HEADER
	req.Header.Set("Auth-Form", dataHeader)
	c, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(c.Username, username+"H")
	assert.Equal(c.Password, passwordH)
	assert.Equal(c.Action, action+"H")
	assert.Equal(c.Csrf, csrf+"H")

	// POST & HEADER, valid HEADER
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Auth-Form", dataHeader)
	c, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(c.Username, username+"H")
	assert.Equal(c.Password, passwordH)
	assert.Equal(c.Action, action+"H")
	assert.Equal(c.Csrf, csrf+"H")

	// POST & HEADER, invalid HEADER
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Auth-Form", "FAKE")
	c, err = GetCredentials(req)
	assert.NoError(err)
	assert.Equal(c.Username, username)
	assert.Equal(c.Password, password)
	assert.Equal(c.Action, action)
	assert.Equal(c.Csrf, csrf)

	// POST & HEADER, invalid HEADER and invalid POST
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader("FAKE"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Auth-Form", "FAKE")
	c, err = GetCredentials(req)
	assert.EqualError(err, "Credentials : No username found in Form")
	assert.Nil(c)

}
