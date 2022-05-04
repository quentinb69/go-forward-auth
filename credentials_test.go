package main

import (
	"testing"
	//	"net/http"

	"github.com/stretchr/testify/assert"
)

var cred = Credentials{
	Username: "Test",
	Password: "0000",
	Action:   "none",
	Csrf:     "none",
}

func TestIsValid(t *testing.T) {
	assert := assert.New(t)
	bcrypt0000 := "$2a$05$5Q7AIdXjMaiCnd2VZYNlke7PskIgXNaaOKrUVIa787VUU5L5usooG"
	bcrypt1111 := "$2a$05$JQKwvqAyG1SzDEr.jkp3Ke1YEDwt1XVkrvjG/0bj5eb8o9CHX0VWi"

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

func TestGetCredentialFromPost(t *testing.T) {
	t.Fail()
}

func TestGetCredentialFromHeader(t *testing.T) {
	t.Fail()
}
