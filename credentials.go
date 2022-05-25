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
	Password string `schema:"password,required"`
	Username string `schema:"username,required"`
	Action   string `schema:"action"`
	Csrf     string `schema:"csrf"`
}

// Validate credentials against user list supplied in configuration file
// return an error if no user configured, or if password is empty, or if password do not match
func (c Credentials) IsValid() (err error) {

	// If user list is empty
	if configuration.Users == nil || len(configuration.Users) == 0 {
		return errors.New("credentials: no user available")
	}

	// Get the expected password from user name (hashed)
	expectedUser, ok := configuration.Users[c.Username]

	// if password is not supplied
	if !ok || expectedUser.Password == "" {
		return errors.New("credentials: bad password supplied for user")
	}

	// Compare hashes
	return IsValidHash(c.Password, expectedUser.Password)
}

// Extract Credentials from request HEADER or BODY
// return an error if credentials are invalid or inexistant
func GetCredentials(r *http.Request) (creds *Credentials, err error) {

	creds, err = GetCredentialsFromHeader(r)
	if err != nil {
		log.Printf("credentials: error from header\n\t-> %s", err)
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
func GetCredentialsFromForm(r *http.Request) (creds *Credentials, err error) {

	if r.Method != http.MethodPost {
		return nil, errors.New("credentials: you must send data via post")
	}

	err = r.ParseForm()

	if err != nil {
		return nil, errors.New("credentials: error parsing form\n\t-> " + err.Error())
	}

	creds = &Credentials{}
	// Get the body and decode into credentials
	if err = decoder.Decode(creds, r.Form); err != nil {
		return nil, errors.New("credentials: error decoding form data\n\t-> " + err.Error())
	}
	return creds, nil
}

// Extract Credentials from request HEADER
// return an error if no header "Auth-Form", or no crendentials data found
func GetCredentialsFromHeader(r *http.Request) (creds *Credentials, err error) {

	// Get value from "Auth-Form" Header
	urlCreds, err := url.ParseQuery(r.Header.Get("Auth-Form"))

	if err != nil {
		return nil, errors.New("credentials: error parsing header\n\t-> " + err.Error())
	}

	creds = &Credentials{}
	// Get the body and decode into credentials
	if err = decoder.Decode(creds, urlCreds); err != nil {
		return nil, errors.New("credentials: error decoding header data\n\t-> " + err.Error())
	}
	return creds, nil
}
