package main

import (
	"net/http"
	"strings"
	"html"
	"crypto/rand"

	"golang.org/x/crypto/bcrypt"
)

func SanitizeIp(ip string) string {
        ip = strings.Replace(ip, "\n", "", -1)
        ip = strings.Replace(ip, "\r", "", -1)
        ip = strings.Replace(ip, " ", "", -1)
        return html.EscapeString(ip)
}

// get user ip
func GetIp(r *http.Request) string {

        ip := SanitizeIp(r.Header.Get("X-Real-IP"))
        if ip == "" {
                ip = SanitizeIp(r.Header.Get("X-Forwarded-For"))
        }
        if ip == "" {
                ip = SanitizeIp(r.RemoteAddr)
        }
        // if multiple ips, get the first
        ip = strings.Split(ip, ",")[0]
        // extact IP from <ip>:<port>
	ip = strings.Split(ip, ":")[0]
	return ip
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
