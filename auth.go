package main

import (
	"log"
)

type User struct {
	Username       string
	Name           string   `koanf:"Name"`
	Password       string   `koanf:"Password"`
	AllowedDomains []string `koanf:"AllowedDomains"`
}

// Return valid user password and ip
func GetValidUser(username, password, url string) *User {

	u := GetUser(username)
	if u == nil {
		log.Printf("user: %s not found", username)
		return nil
	}

	if !CompareHash(u.Password, password) {
		log.Printf("user: %s bad password", username)
		return nil
	}

	if !u.Allowed(url) {
		return nil
	}

	return u
}

// verify user allowed domains
func (u *User) Allowed(url string) (ret bool) {
	ret = CompareDomains(u.AllowedDomains, url)
	if !ret {
		log.Printf("user: %s not allowed domain %s", u.Name, url)
	}
	return ret
}

// find user from configuration
func GetUser(username string) *User {
	if configuration.Users == nil || len(configuration.Users) == 0 {
		log.Print("user: no user configured")
		return nil
	}

	u, ok := configuration.Users[username]
	if !ok {
		return nil
	}

	u.Username = username
	return u
}
