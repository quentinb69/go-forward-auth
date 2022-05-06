package main

import (
	"errors"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/schema"
)

// Parse http request to a Credentials struct
var decoder = schema.NewDecoder()

// Action and Csrf not used...
type Credentials struct {
	Password string `schema:password,required`
	Username string `schema:username,required`
	Action   string `schema:action,required`
	Csrf     string `schema:csrf,required`
}

// Validate credentials against user list supplied in configuration file
// return an error if no user configured, or if password is empty, or if password do not match
func (c Credentials) IsValid() error {

	// If user list is empty
	if configuration.Users == nil || len(configuration.Users) == 0 {
		return errors.New("Credentials : No user available")
	}

	// Get the expected password from user name (hashed)
	expectedPassword, ok := configuration.Users[c.Username]

	// if password is not supplied
	if !ok || expectedPassword == "" {
		return errors.New("Credentials : No password supplied for user")
	}

	// Compare hashes
	return IsValidHash(c.Password, expectedPassword)
}

// Extract Credentials from request HEADER or BODY
// return an error if credentials are invalid or inexistant
func GetCredentials(r *http.Request) (*Credentials, error) {

	creds, err := GetCredentialsFromHeader(r)
	if err != nil {
		log.Printf("Getting Credentials from Form. %s", err)
		creds, err = GetCredentialsFromForm(r)
		// no creds supplied
		if err != nil {
			return nil, err
		}
	}

	// Check if creds are valid
	err = creds.IsValid()
	return creds, err
}

// Extract Credentials from request BODY
// return an error if method other than POST, or no crendentials data found
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

// Extract Credentials from request HEADER
// return an error if no header "Auth-Form", or no crendentials data found
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
