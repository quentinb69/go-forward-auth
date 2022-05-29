package main

import (
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/schema"
)

// Parse http request to a FormData struct
var decoder = schema.NewDecoder()

// Action not used...
type FormData struct {
	Password string `schema:"password,required"`
	Username string `schema:"username,required"`
	Csrf     string `schema:"csrf"`
	Action   string `schema:"action"`
}

// Extract FormData from request HEADER
func GetFormData(r *http.Request) (f *FormData) {

	// Get value from "Auth-Form" Header, no need to error check
	urlCreds, _ := url.ParseQuery(r.Header.Get("Auth-Form"))

	f = &FormData{}
	// Get the body and decode into FormData
	if err := decoder.Decode(f, urlCreds); err != nil {
		log.Printf("formdata: error decoding formdata\n\t-> %v", err)
		return nil
	}

	return f
}

// Generate FormData
func GenerateFormData(username string) *FormData {
	return &FormData{
		Username: username,
	}
}

// Validate FormData and user
func GetValidUserFromFormData(f *FormData, url string) *User {
	if f == nil {
		log.Print("formdata: no formdata provided")
		return nil
	}

	if f.Password == "" || f.Username == "" {
		log.Print("formdata: missing password or username")
		return nil
	}

	return GetValidUser(f.Username, f.Password, url)
}
