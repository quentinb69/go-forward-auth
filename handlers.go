package main

import (
	"html/template"
	"log"
	"net/http"
	"time"
)

// Return HTML
func RenderTemplate(w *http.ResponseWriter, claims *Claims, ip string, httpCode int, state string) {

	data := make(map[string]string)
	data["ip"] = ip
	data["csrf"] = "TODO"
	data["state"] = state

	// Login ok
	if claims != nil {
		data["username"] = claims.Username
		// return logged-in user in header
		(*w).Header().Add("Remote-User", claims.Username)
	}

	// load template
	parsedTemplate, _ := template.ParseFiles(configuration.HtmlFile)
	// return http code and html
	(*w).WriteHeader(httpCode)
	err := parsedTemplate.Execute(*w, data)
	if err != nil {
		panic(err)
	}

	return
}

// LOGOUT HANDLER
// return 401 if not logged in
// return 302 if diconnected
func Logout(w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)
	_, _, err := GetClaims(r, ip)

	// no or invalid jwt supplied
	if err != nil {
		log.Printf("Handler : Invalid JWT for : %s - %v", ip, err)
		time.Sleep(500 * time.Millisecond)
		http.Redirect(w, r, "/", 401)
		return
	}

	// remove cookie
	http.SetCookie(w, &http.Cookie{
		Name:     configuration.CookieName,
		Value:    "",
		Expires:  time.Now(),
		Domain:   configuration.CookieDomain,
		MaxAge:   -1,
		Secure:   configuration.Tls,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// return if disconnected
	log.Printf("Handler : Logout for: %s", ip)
	http.Redirect(w, r, "/", 302)
	return
}

// LOGIN HANDLER
// return 302 if login ok
// return 401 if login ko
func Login(w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)
	credentials, err := GetCredentials(r)

	// no or invalid credentials supplied
	if err != nil {
		log.Printf("Failed attempt for: %s - %v", ip, err)
		time.Sleep(500 * time.Millisecond)
		http.Redirect(w, r, "/", 401)
		return
	}

	CreateOrExtendJwt(&w, credentials, ip, nil, nil)

	// return if connected
	log.Printf("Handler : Login for: %s", ip)
	http.Redirect(w, r, "/", 302)
	return
}

// DEFAULT HANDLER
func Home(w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)
	state := "out" // logged-in or logged-out

	claims, cookie, err := GetClaims(r, ip)

	// no or invalid jwt supplied
	if err != nil {

		log.Printf("Handler : Invalid JWT for : %s - %v", ip, err)
		credentials, err := GetCredentials(r)

		// no or invalid credentials supplied
		if err != nil {
			log.Printf("Handler : Invalid Credentials for : %s - %v", ip, err)
			// fake waiting time to limit brute force
			time.Sleep(500 * time.Millisecond)
			RenderTemplate(&w, claims, ip, http.StatusUnauthorized, state)
			return
		}

		// valid credentials supplied
		log.Printf("Handler : Creating Jwt for: %s", ip)
		claims, err = CreateOrExtendJwt(&w, credentials, ip, claims, cookie)
		RenderTemplate(&w, claims, ip, 300, state)
		return
	}

	// valid jwt supplied
	state = "in"
	needRefresh := time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) < configuration.TokenRefresh

	// jwt can be extended (<10% left time)
	if needRefresh {
		log.Printf("Handler : Refreshing Jwt for: %s", ip)
		claims, err = CreateOrExtendJwt(&w, nil, ip, claims, cookie)
		RenderTemplate(&w, claims, ip, 300, state)
		return
	}

	//log.Printf("Home for: %s", ip)
	RenderTemplate(&w, claims, ip, http.StatusOK, state)
	return
}
