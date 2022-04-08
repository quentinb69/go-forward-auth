package main

import (
	"net/http"
	"strings"
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
