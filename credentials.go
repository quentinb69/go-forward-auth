package main

import (
	"errors"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/schema"
)

// global
var decoder = schema.NewDecoder()

type Credentials struct {
	Password string `schema: password,required`
	Username string `schema: username,required`
	Action   string `schema: action,required`
	Csrf     string `schema: csrf,required`
}

func (c Credentials) IsValid() error {

	// if user list is empty
	if configuration.Users == nil || len(configuration.Users) == 0 {
		return errors.New("Credentials : No user available")
	}

	// Get the expected password from user name (hashed)
	expectedPassword, ok := configuration.Users[c.Username]

	// if password is not supplied
	if !ok || expectedPassword == "" {
		return errors.New("Credentials : No password supplied for user")
	}

	// compare hashes
	return IsValidHash(c.Password, expectedPassword)
}

// Wrapper to get Credentials form POST or HEADER
func GetCredentials(r *http.Request) (*Credentials, error) {

	creds, err := GetCredentialsFromHeader(r)
	if err != nil {
		log.Printf("Get Credentials from POST, %s", err)
		creds, err = GetCredentialsFromPost(r)
		// no creds supplied
		if err != nil {
			return creds, err
		}
	}

	// check if creds are valid
	err = creds.IsValid()
	return creds, err
}

// Extract Credentials from POST
func GetCredentialsFromPost(r *http.Request) (*Credentials, error) {

	creds := &Credentials{}

	err := r.ParseForm()
	if err != nil {
		return nil, err
	}

	// Get the body and decode into credentials
	err = decoder.Decode(creds, r.Form)
	return creds, err
}

// Extract Credentials from HEADER
func GetCredentialsFromHeader(r *http.Request) (*Credentials, error) {

	creds := &Credentials{}

	// Get value from "Auth-Form" Header
	urlCreds, err := url.ParseQuery(r.Header.Get("Auth-Form"))
	if err != nil {
		return nil, err
	}

	err = decoder.Decode(creds, urlCreds)
	return creds, err
}
