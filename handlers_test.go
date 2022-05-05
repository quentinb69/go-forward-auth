package main

import (
	"net/http"
    //"net/http/httptest"
    "testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderTemplate(t *testing.T) {
	t.Fail()
}

func TestLogout(t *testing.T) {
	t.Fail()
}

func TestLogin(t *testing.T) {
	t.Fail()
}

func TestHome(t *testing.T) {
	assert := assert.New(t)
	
	// no JWT no CRED
    handler := http.HandlerFunc(Home)
	assert.HTTPStatusCode(handler, "GET", "/home", nil, 401)
	assert.HTTPBodyContains(handler, "GET", "/home", nil, "Login</button>")

/*
	// no JWT no CRED
	req, _ := http.NewRequest("POST", "http://localhost/", nil)
	Home(wr, req)
	assert.EqualError(err, "")

	// no JWT bad CRED
	req, _ = http.NewRequest("POST", "http://localhost/", nil)
	assert.EqualError(err, "")

	// bad JWT no CRED
	req, _ = http.NewRequest("POST", "http://localhost/", nil)
	assert.EqualError(err, "")

	// bad JWT bad CRED
	req, _ = http.NewRequest("POST", "http://localhost/", nil)
	assert.EqualError(err, "")

	// bad JWT good CRED
	req, _ = http.NewRequest("POST", "http://localhost/", nil)
	assert.EqualError(err, "")

	// good JWT
	req, _ = http.NewRequest("POST", "http://localhost/", nil)
	assert.NoError(err)
*/
}