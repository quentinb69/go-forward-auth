package main

import (
	"crypto/rand"
	"html"
	"net/http"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// return sanitized ip
func GetSanitizeIp(ip string) string {
	ip = strings.Replace(ip, "\n", "", -1)
	ip = strings.Replace(ip, "\r", "", -1)
	ip = strings.Replace(ip, " ", "", -1)
	return html.EscapeString(ip)
}

// get user ip from request
func GetIp(r *http.Request) (ip string) {

	ip = GetSanitizeIp(r.Header.Get("X-Real-IP"))
	if ip == "" {
		ip = GetSanitizeIp(r.Header.Get("X-Forwarded-For"))
	}
	if ip == "" {
		ip = GetSanitizeIp(r.RemoteAddr)
	}
	// if multiple ips, get the first
	ip = strings.Split(ip, ",")[0]
	// extact IP from <ip>:<port> with ipv6 in mind
	splittedIp := strings.Split(ip, ":")
	if len(splittedIp) > 1 {
		ip = strings.Join(splittedIp[:len(splittedIp)-1], ":")
	}
	return
}

// get host from request
func GetHost(r *http.Request) (host string) {
	host = r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return host
}

// return bcrypted hash of string
// panic in case of error
func GetHash(s string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(s), configuration.HashCost)
	if err != nil {
		panic(err)
	}
	return string(h)
}

// compare a hash with a hashed string
func CompareHash(h string, s string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(h), []byte(s))
	return err == nil
}

// generate random bytes
func GenerateRandomBytes(n uint) *[]byte {
	ret := make([]byte, n)
	rand.Read(ret)
	return &ret
}

// extract domain from url
func GetDomain(url string) string {
	//remove port from url
	splittedUrl := strings.Split(url, ":")
	if len(splittedUrl) > 1 {
		url = strings.Join(splittedUrl[:len(splittedUrl)-1], ":")
	}
	return url
}

// compare domain from url with domains list
func CompareDomains(domains []string, url string) bool {
	domain := GetDomain(url)
	//valid domain against regexp
	for _, d := range domains {
		match, _ := regexp.MatchString(d+"$", domain)
		if match {
			return true
		}
	}
	return false
}
