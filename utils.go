package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"html"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// return sanitized value
func GetSanitizeHeader(str string) string {
	str = strings.Replace(str, "\n", "", -1)
	str = strings.Replace(str, "\r", "", -1)
	str = strings.Replace(str, " ", "", -1)
	return html.EscapeString(str)
}

// get user ip from request
func GetIp(r *http.Request) (ip string) {

	ip = GetSanitizeHeader(r.Header.Get("X-Real-IP"))
	if ip == "" {
		ip = GetSanitizeHeader(r.Header.Get("X-Forwarded-For"))
	}
	if ip == "" {
		ip = GetSanitizeHeader(r.RemoteAddr)
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
	host = GetDomain(GetSanitizeHeader(r.Header.Get("X-Original-URL")))
	if host == "" {
		host = GetDomain(GetSanitizeHeader(r.Header.Get("X-Forwarded-Host")))
	}
	if host == "" {
		host = GetDomain(GetSanitizeHeader(r.Host))
	}
	return host
}

// return bcrypted hash of string, 12 iterations
// panic in case of error
func GetHash(s string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(s), 12)
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
	// remove protocol from url (output domain.com:port/path)
	splittedUrl := strings.Split(url, "//")
	if len(splittedUrl) > 1 {
		url = strings.Join(splittedUrl[1:], "//")
	} else {
		url = splittedUrl[0]
	}
	// remove path from url (output domain.com:port)
	url = strings.Split(url, "/")[0]
	//remove port from url (careful, url can be ipv6) (output domain.com)
	splittedUrl = strings.Split(url, ":")
	if len(splittedUrl) > 1 {
		url = strings.Join(splittedUrl[:len(splittedUrl)-1], ":")
	} else {
		url = splittedUrl[0]
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

// generate private and public keys, return if file exists, panic if impossible to finish
func GenerateKeyPair(keySize int, privateKeyFile string, certificateFile string) {
	if _, err := os.Stat(privateKeyFile); err == nil {
		return
	}
	if _, err := os.Stat(certificateFile); err == nil {
		return
	}

	priv, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"GFA"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &(priv).PublicKey, priv)
	if err != nil {
		panic(err)
	}
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	err = os.WriteFile(certificateFile, out.Bytes(), 0400)
	if err != nil {
		panic(err)
	}

	out.Reset()
	pem.Encode(out, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	err = os.WriteFile(privateKeyFile, out.Bytes(), 0400)
	if err != nil {
		panic(err)
	}
}
