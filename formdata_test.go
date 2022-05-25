package main

/*
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

	f := formData

	// No user
	configuration.Users = nil
	err := f.IsValid()
	assert.EqualError(err, "FormData: no user available")

	configuration.Users = map[string]User{}
	err = f.IsValid()
	assert.EqualError(err, "FormData: no user available")

	// bad user-password
	configuration.Users = map[string]User{"TEST2": {Password: "TOTO"}}
	err = f.IsValid()
	assert.EqualError(err, "FormData: bad password supplied for user")

	configuration.Users = map[string]User{"TEST2": {Password: "TOTO"}, f.Username: {Password: ""}}
	err = f.IsValid()
	assert.EqualError(err, "FormData: bad password supplied for user")

	configuration.Users = map[string]User{"TEST2": {Password: "TOTO"}, f.Username: {Password: globBcrypt1111}}
	err = f.IsValid()
	assert.EqualError(err, "crypto/bcrypt: hashedPassword is not the hash of the given password")

	// valid
	configuration.Users = map[string]User{"TEST2": {Password: "TOTO"}, f.Username: {Password: globBcrypt0000}}
	err = f.IsValid()
	assert.NoError(err)

}

func TestGetFormDataFromForm(t *testing.T) {
	assert := assert.New(t)

	c := &FormData{}

	// no data
	req, _ := http.NewRequest("POST", "http://localhost", nil)
	err := c.FromBody(req)
	assert.ErrorContains(err, "error parsing form")
	assert.Nil(c)

	// method GET
	req, _ = http.NewRequest("GET", "http://localhost?"+globData, nil)
	err = c.FromBody(req)
	assert.EqualError(err, "FormData: you must send data via post")
	assert.Nil(c)

	// no username
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globDataNoUsername))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err = c.FromBody(req)
	assert.ErrorContains(err, "error decoding form")
	assert.Nil(c)

	// no password
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globDataNoPassword))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err = c.FromBody(req)
	assert.ErrorContains(err, "error decoding form")
	assert.Nil(c)

	// valid
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err = c.FromBody(req)
	assert.NoError(err)
	assert.Equal(globUsername, c.Username)
	assert.Equal(globPassword, c.Password)
	assert.Equal(globAction, c.Action)
	assert.Equal(globCsrf, c.Csrf)
}

func TestGetFormDataFromHeader(t *testing.T) {
	assert := assert.New(t)

	c := &FormData{}
	// no data
	req, _ := http.NewRequest("POST", "http://localhost", nil)
	err := c.FromHeader(req)
	assert.ErrorContains(err, "error decoding header")
	assert.Nil(c)

	// no username
	req.Header = *headersFormData["nousername"]
	err = c.FromHeader(req)
	assert.ErrorContains(err, "error decoding header")
	assert.Nil(c)

	// no password
	req.Header = *headersFormData["nopassword"]
	err = c.FromHeader(req)
	assert.ErrorContains(err, "error decoding header")
	assert.Nil(c)

	// valid
	req.Header = *headersFormData["valid"]
	err = c.FromHeader(req)
	assert.NoError(err)
	assert.Equal(globUsername, c.Username)
	assert.Equal(globPassword, c.Password)
	assert.Equal(globAction, c.Action)
	assert.Equal(globCsrf, c.Csrf)
}

func TestGetFormData(t *testing.T) {
	assert := assert.New(t)

	c := &FormData{}
	// GET
	req, _ := http.NewRequest("GET", "http://localhost/?"+globData, nil)
	err := c.FromRequest(req)
	assert.EqualError(err, "FormData: you must send data via post")
	assert.Nil(c)

	// POST
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globData))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	err = c.FromRequest(req)
	assert.NoError(err)
	assert.Equal(globUsername, c.Username)
	assert.Equal(globPassword, c.Password)
	assert.Equal(globAction, c.Action)
	assert.Equal(globCsrf, c.Csrf)

	// HEADER
	req.Header = *headersFormData["validH"]
	err = c.FromRequest(req)
	assert.NoError(err)
	assert.Equal(globUsername+"H", c.Username)
	assert.Equal(globPasswordH, c.Password)
	assert.Equal(globAction+"H", c.Action)
	assert.Equal(globCsrf+"H", c.Csrf)

	// POST & HEADER, valid HEADER
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globData))
	req.Header = *headersFormData["validH"]
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	err = c.FromRequest(req)
	assert.NoError(err)
	assert.Equal(globUsername+"H", c.Username)
	assert.Equal(globPasswordH, c.Password)
	assert.Equal(globAction+"H", c.Action)
	assert.Equal(globCsrf+"H", c.Csrf)

	// POST & HEADER, invalid HEADER
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader(globData))
	req.Header = *headersFormData["fake"]
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	err = c.FromRequest(req)
	assert.NoError(err)
	assert.Equal(globUsername, c.Username)
	assert.Equal(globPassword, c.Password)
	assert.Equal(globAction, c.Action)
	assert.Equal(globCsrf, c.Csrf)

	// POST & HEADER, invalid HEADER and invalid POST
	req, _ = http.NewRequest("POST", "http://localhost", strings.NewReader("FAKE"))
	req.Header = *headersFormData["fake"]
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	err = c.FromRequest(req)
	assert.ErrorContains(err, "FormData: error decoding form")
	assert.Nil(c)
}
*/
