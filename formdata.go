package main

import (
	"errors"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/schema"
)

// Parse http request to a FormData struct
var decoder = schema.NewDecoder()

// Action and Csrf not used...
type FormData struct {
	Password    string `schema:"password,required"`
	Username    string `schema:"username,required"`
	Action      string `schema:"action"`
	Csrf        string `schema:"csrf"`
	Ip          string
	customValid bool
}

func (f *FormData) CustomValid() error {
	if f == nil {
		return errors.New("formdata: no formdata provided")
	}

	f.customValid = false
	if f.Password == "" || f.Username == "" || f.Ip == "" {
		return errors.New("formdata: missing password or username or ip")
	}
	f.customValid = true
	return nil
}

// Create FormData from request HEADER or BODY
// return an error if no or invalid data
func GetValidFormDataFromRequest(r *http.Request, ip string) (f *FormData, err error) {

	f, err = GetValidFormDataFromHeader(r, ip)
	if err != nil {
		log.Printf("formdata: error from header\n\t-> %s", err)
		return GetValidFormDataFromBody(r, ip)
	}
	return f, nil
}

// Extract FormData from request BODY
// return an error if method other than POST, or no crendentials data found
func GetValidFormDataFromBody(r *http.Request, ip string) (f *FormData, err error) {

	if r.Method != http.MethodPost {
		return nil, errors.New("formdata: you must send data via post")
	}

	err = r.ParseForm()

	if err != nil {
		return nil, errors.New("formdata: error parsing form\n\t-> " + err.Error())
	}

	f = &FormData{}
	// Get the body and decode into FormData
	if err = decoder.Decode(f, r.Form); err != nil {
		return nil, errors.New("formdata: error decoding form data\n\t-> " + err.Error())
	}
	f.Ip = ip

	return f, f.CustomValid()
}

// Extract FormData from request HEADER
// return an error if no header "Auth-Form", or no crendentials data found
func GetValidFormDataFromHeader(r *http.Request, ip string) (f *FormData, err error) {

	// Get value from "Auth-Form" Header
	urlCreds, err := url.ParseQuery(r.Header.Get("Auth-Form"))

	if err != nil {
		return nil, errors.New("formdata: error parsing header\n\t-> " + err.Error())
	}

	f = &FormData{}
	// Get the body and decode into FormData
	if err = decoder.Decode(f, urlCreds); err != nil {
		return nil, errors.New("formdata: error decoding header data\n\t-> " + err.Error())
	}
	f.Ip = ip

	return f, f.CustomValid()
}
