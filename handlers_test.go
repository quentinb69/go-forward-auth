package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderTemplate(t *testing.T) {

	//TODO test rendering
	t.Skip()

	assert := assert.New(t)
	w := new(http.ResponseWriter)
	c := claims
	code := 999

	// state in and laims
	RenderTemplate(w, &c, globValidIp, code, "in")
	assert.Equal(999, w)

	// state in No claims
	RenderTemplate(w, &c, globValidIp, code, "in")
	assert.Equal(999, w)

	// state out
	RenderTemplate(w, &c, globValidIp, code, "out")
	assert.Equal(999, w)
}

func TestLogout(t *testing.T) {
	assert := assert.New(t)
	co := cookies["valid"]
	handler := http.HandlerFunc(Logout)

	// no JWT no CRED
	req := httptest.NewRequest("POST", "/logout", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	resp := w.Result()
	assert.Equal(401, resp.StatusCode)

	// bad JWT
	req = httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&co)
	w = httptest.NewRecorder()
	handler(w, req)
	resp = w.Result()
	assert.Equal(401, resp.StatusCode)

	// good JWT
	req = httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&co)
	req.RemoteAddr = globValidIp
	w = httptest.NewRecorder()
	handler(w, req)
	resp = w.Result()
	assert.Equal(302, resp.StatusCode)
}

func TestHome(t *testing.T) {
	assert := assert.New(t)
	co := cookies["valid"]
	handler := http.HandlerFunc(Home)

	// no JWT no CRED
	req := httptest.NewRequest("POST", "/home", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(401, resp.StatusCode)
	assert.Contains(string(body), "Login</button>")

	// bad JWT no CRED
	req = httptest.NewRequest("POST", "/home", nil)
	w = httptest.NewRecorder()
	req.AddCookie(&co)
	handler(w, req)
	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(401, resp.StatusCode)
	assert.Contains(string(body), "Login</button>")

	// no JWT bad CRED
	req = httptest.NewRequest("POST", "/home", nil)
	req.Header.Set("Auth-Form", globDataNoPassword)
	w = httptest.NewRecorder()
	handler(w, req)
	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(401, resp.StatusCode)
	assert.Contains(string(body), "Login</button>")

	// bad JWT bad CRED
	req = httptest.NewRequest("POST", "/home", nil)
	req.Header.Set("Auth-Form", globDataNoPassword)
	req.AddCookie(&co)
	w = httptest.NewRecorder()
	handler(w, req)
	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(401, resp.StatusCode)
	assert.Contains(string(body), "Login</button>")

	// bad JWT good CRED
	req = httptest.NewRequest("POST", "/home", nil)
	req.Header.Set("Auth-Form", globData)
	req.AddCookie(&co)
	w = httptest.NewRecorder()
	handler(w, req)
	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(300, resp.StatusCode)
	assert.Contains(string(body), "Welcome")

	// good JWT
	req = httptest.NewRequest("POST", "/home", nil)
	req.AddCookie(&co)
	req.RemoteAddr = globValidIp
	w = httptest.NewRecorder()
	handler(w, req)
	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(200, resp.StatusCode)
	assert.Contains(string(body), "Welcome")

	//TODO test extend jwt
}
