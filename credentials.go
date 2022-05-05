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
		log.Printf("Getting Credentials from Form, %s, %v", err, creds)
		creds, err = GetCredentialsFromForm(r)
		// no creds supplied
		if err != nil {
			return nil, err
		}
	}

	// check if creds are valid
	err = creds.IsValid()
	return creds, err
}

// Extract Credentials from POST
func GetCredentialsFromForm(r *http.Request) (*Credentials, error) {

	if r.Method != http.MethodPost {
		return nil, errors.New("Credentials : You must send data via POST")
	}

	err := r.ParseForm()
	if err != nil {
		return nil, err
	}
	if r.Form.Get("username") == "" {
		return nil, errors.New("Credentials : No username found in Form")
	}

	// Get the body and decode into credentials
	creds := &Credentials{}
	err = decoder.Decode(creds, r.Form)
	return creds, err
}

// Extract Credentials from HEADER
func GetCredentialsFromHeader(r *http.Request) (*Credentials, error) {

	// Get value from "Auth-Form" Header
	urlCreds, err := url.ParseQuery(r.Header.Get("Auth-Form"))
	if err != nil {
		return nil, err
	}
	if urlCreds.Get("username") == "" {
		return nil, errors.New("Credentials : No username found in Header")
	}
	creds := &Credentials{}
	err = decoder.Decode(creds, urlCreds)
	return creds, err
}
