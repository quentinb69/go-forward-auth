package main

import (
	"net/http"
	"time"
	"log"
	"errors"

	"github.com/google/uuid"
)

//global
var sessions = map[string]Session{}

type Session struct {
        username string
        ip string
        expiry   time.Time
}

func (s Session) isExpired() bool {
        return s.expiry.Before(time.Now())
}

func (s Session) isInvalidIp(ip string) bool {
        return s.ip != ip
}

// Create or extend Session duration
func CreateOrExtendSession (w *http.ResponseWriter, creds *Credentials, ip string, session *Session, cookie *http.Cookie ) *Session {

        newSessionToken := uuid.NewString()
        expiresAt := time.Now().Add(configuration.Expire * time.Second * 60)
	var username string
	var userIp string

	// get values from session or from creds
	if session != nil {
		log.Printf("Extend session for: %s", session.ip)
		username = session.username
		userIp = session.ip
		delete(sessions, cookie.Value)
	} else {
		log.Printf("Create session for: %s", ip)
		username = creds.Username
		userIp = ip
	}

        // declare session
	sessions[newSessionToken] = Session{
                username: username,
                ip:       userIp,
                expiry:   expiresAt,
        }

	// add or update cookie
        http.SetCookie(*w, &http.Cookie{
                Name:    configuration.CookieName,
                Value:   newSessionToken,
                Expires: expiresAt,
		Domain:  configuration.CookieDomain,
		Path:    "/",
        })

	returnSession := sessions[newSessionToken]
        return &returnSession
}

func RemoveSession (cookie *http.Cookie) {
	delete(sessions, cookie.Value)
	return
}

// Get session from request
func GetSession (r *http.Request, ip string) (*Session, *http.Cookie, error) {

	session := &Session{}

        // get session token
        cookie, err := r.Cookie(configuration.CookieName)
        if err != nil {
                return nil, cookie, err
        }

        sessionTmp, exists := sessions[cookie.Value]

        if !exists {
                return nil, cookie, errors.New("No session")
        }
	session = &sessionTmp
        if session.isExpired() {
		RemoveSession (cookie)
                return session, cookie, errors.New("Session expired")
        }
        if session.isInvalidIp(ip) {
		RemoveSession (cookie)
                return session, cookie, errors.New("Session invalid")
        }

        return session, cookie, nil
}
