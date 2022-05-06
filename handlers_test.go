package main

import (
	"net/http"
    "net/http/httptest"
    "testing"
	"io"

	"github.com/stretchr/testify/assert"
)

func TestRenderTemplate(t *testing.T) {
	t.Fail()
}

func TestLogout(t *testing.T) {
	assert := assert.New(t)

	// no JWT no CRED
    handler := http.HandlerFunc(Logout)
	assert.HTTPStatusCode(handler, "GET", "/logout", nil, 401)
	assert.HTTPBodyContains(handler, "GET", "/logout", nil, "Unauthorized")
	t.Fail()
}

func TestLogin(t *testing.T) {
	assert := assert.New(t)

	// no JWT no CRED
    handler := http.HandlerFunc(Login)
	assert.HTTPStatusCode(handler, "GET", "/login", nil, 401)
	assert.HTTPBodyContains(handler, "GET", "/login", nil, "Unauthorized")

	t.Fail()
}

func TestHome(t *testing.T) {
	assert := assert.New(t)
	w := httptest.NewRecorder()

	// no JWT no CRED
    handler := http.HandlerFunc(Home)
	assert.HTTPStatusCode(handler, "GET", "/home", nil, 401)
	assert.HTTPBodyContains(handler, "GET", "/home", nil, "Login</button>")


	// bad JWT no CRED
	co := cookies["fake"]
	req := httptest.NewRequest("POST", "/home", nil)
	req.AddCookie(&co)
	handler(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(resp.StatusCode, 401)
	assert.Contains(string(body), "Login</button>")

/*
	// no JWT bad CRED
	req, _ = http.NewRequest("POST", "http://localhost/", nil)
	assert.EqualError(err, "")

	
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