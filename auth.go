package main

import "go.uber.org/zap"

type User struct {
	Username       string
	Password       string   `koanf:"Password"`
	AllowedDomains []string `koanf:"AllowedDomains"`
}

// Return valid user password and ip
func GetValidUser(username, password, url string) *User {

	u := GetUser(username)
	if u == nil {
		log.Info("user: not found", zap.String("username", username))
		return nil
	}

	if !CompareHash(u.Password, password) {
		log.Error("user: bad password", zap.String("username", username))
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
		log.Error("user: not allowed", zap.String("username", u.Username), zap.String("url", url))
	}
	return ret
}

// find user from configuration
func GetUser(username string) *User {
	if configuration.Users == nil || len(configuration.Users) == 0 {
		log.Info("user: no user configured")
		return nil
	}

	u, ok := configuration.Users[username]
	if !ok {
		return nil
	}

	u.Username = username
	return u
}
