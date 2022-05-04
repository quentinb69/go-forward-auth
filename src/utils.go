package main

import (
	"net/http"
	"strings"
	"html"
	"crypto/rand"

	"golang.org/x/crypto/bcrypt"
)

// get user ip
func GetIp(r *http.Request) string {

        ip := r.Header.Get("X-Real-IP")
        if ip == "" {
                ip = r.Header.Get("X-Forwarded-For")
        }
        if ip == "" {
                ip = r.RemoteAddr
        }
        // if multiple ips, get the first
        ip = strings.Split(ip, ":")[0]
	// sanitize
	escapedIp := strings.Replace(ip, "\n", "", -1)
	escapedIp = strings.Replace(ip, "\r", "", -1)
	return html.EscapeString(escapedIp)
}

func GetHash(s string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(s), configuration.HashCost)
	return string(h), err
}

// compare a hash with a hashed string
func IsValidHash(s string, h string) error {
	return bcrypt.CompareHashAndPassword([]byte(h), []byte(s))
}

// generate random bytes
func GenerateRand(s uint) (*[]byte, error) {
	ret := make([]byte, s)
	_, err := rand.Read(ret)
	return &ret, err
}
