package main

import (
	"net/http"
	"html/template"
	"time"
	"log"
)

// Return HTML
func RenderTemplate (w *http.ResponseWriter, session *Session, ip string, httpCode int) {

	data := make(map[string]string)
	data["ip"] = ip
	data["csrf"] = "TODO"
	data["state"] = "out"

	// Login ok
	if session != nil {
		data["state"] = "in"
		data["username"] = session.username
	}

	// load template
	parsedTemplate, _ := template.ParseFiles(configuration.HtmlFile)
	// return code and html
	(*w).WriteHeader(httpCode)
	err := parsedTemplate.Execute(*w, data)
	if err != nil {
		panic (err)
	}

	return
}

// LOGOUT HANDLER
// return 401 if not logged in
// return 300 if diconnected
func Logout(w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)
	_, cookie, err := GetSession (r, ip)

	// return 401
	if err != nil {
		log.Printf("Failed attempt for: %s", ip)
		log.Printf("Session error: %s", err)
		time.Sleep(500 * time.Millisecond)
		http.Redirect(w, r, "/", 302)
		return
	}

	// remove session (server) and cookie (client)
	RemoveSession(cookie)
	http.SetCookie(w, &http.Cookie{
		Name:    configuration.CookieName,
		Value:   "",
		Expires: time.Now(),
		Domain:  configuration.CookieDomain,
		Path:    "/",
	})

	// return 200
	log.Printf("Logout for: %s", ip)
	http.Redirect(w, r, "/", http.StatusOK)
	return
}

// LOGIN HANDLER
// return 300 if login ok
// return 401 if login ko
func Login(w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)
	credentials, err := GetCredentials (r)

	// return 401
	if err != nil {
		log.Printf("Failed attempt for: %s", ip)
		log.Printf("Credentials error: %s", err)
		time.Sleep(500 * time.Millisecond)
		http.Redirect(w, r, "/", 302)
		return
	}

        CreateOrExtendSession(&w, credentials, ip, nil, nil)

	// return 200
	log.Printf("Login for: %s", ip)
	http.Redirect(w, r, "/", http.StatusOK)
        return
}

// DEFAULT HANDLER
func Home (w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)
	session, cookie, errSession := GetSession (r, ip)
	credentials, errCredentials := GetCredentials (r)

	// no valid session and no credentials submitted
	if errSession != nil && errCredentials != nil {
		log.Printf("Failed attempt for: %s", ip)
		log.Printf("Session error: %s", errSession)
		log.Printf("Credentials error: %s", errCredentials)
		time.Sleep(500 * time.Millisecond)
		RenderTemplate(&w, session, ip, http.StatusUnauthorized)
		return
	}

	// credentials supplied
	if errCredentials == nil {
		log.Printf("Create session for: %s", ip)
		CreateOrExtendSession(&w, credentials, ip, session, cookie)
		RenderTemplate(&w, session, ip, 300)
		return
	}

	// session exists
	/*if errSession == nil {
		log.Printf("Refresh session for: %s", ip)
		CreateOrExtendSession(&w, credentials, ip, session, cookie)
		RenderTemplate(&w, session, ip, 300)
		return
	}*/

	//log.Printf("Home for: %s", ip)
	RenderTemplate(&w, session, ip, http.StatusOK)
	return
}
