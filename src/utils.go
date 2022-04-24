package main

import (
	"net/http"
	"strings"

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
        return strings.Split(ip, ":")[0]
}

func GetHash(s string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(s), configuration.HashCost)
	return string(h), err
}

// compare a hash with a hashed string
func IsValidHash(s string, h string) error {
	return bcrypt.CompareHashAndPassword([]byte(h), []byte(s))
}

