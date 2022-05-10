package main

import (
	"errors"
	"html/template"
	"log"
	"net/http"
	"time"
)

// Render HTML passed in configuration
func RenderTemplate(w *http.ResponseWriter, claims *Claims, ip string, httpCode int, state string) error {

	if *w == nil {
		return errors.New("handler: responsewriter is mandatory")
	}

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
		return err
	}

	return nil
}

// LOGOUT HANDLER
// return 401 if not logged in
// return 302 if diconnected
func Logout(w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)
	_, err := GetClaims(r, ip)

	// no or invalid jwt supplied
	if err != nil {
		log.Printf("handler: invalid jwt for : %s - %v", ip, err)
		time.Sleep(500 * time.Millisecond)
		http.Redirect(w, r, "/", http.StatusUnauthorized)
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
	log.Printf("handler: logout for: %s", ip)
	http.Redirect(w, r, "/", http.StatusFound)
}

// DEFAULT HANDLER
func Home(w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)
	state := "out" // logged-in or logged-out

	claims, err := GetClaims(r, ip)

	// no or invalid jwt supplied
	if err != nil {

		log.Printf("handler: invalid jwt for : %s - %v", ip, err)
		credentials, err := GetCredentials(r)

		// no or invalid credentials supplied
		if err != nil {
			log.Printf("handler: invalid credentials for : %s - %v", ip, err)
			// fake waiting time to limit brute force
			time.Sleep(500 * time.Millisecond)
			err = RenderTemplate(&w, claims, ip, http.StatusUnauthorized, state)
			if err != nil {
				log.Fatalf("handler: error rendering template - %v", err)
			}
			return
		}

		// valid credentials supplied
		state = "in"
		log.Printf("handler: creating jwt for: %s", ip)
		claims, err = CreateClaims(credentials, ip)
		if err != nil {
			log.Fatalf("handler: error generating claims - %v ", err)
		}
		if err = CreateJwt(&w, claims); err != nil {
			log.Fatalf("handler: new jwt - %v ", err)
		}
		RenderTemplate(&w, claims, ip, http.StatusMultipleChoices, state)
		if err != nil {
			log.Fatalf("handler: error rendering template - %v", err)
		}
		return
	}

	// valid jwt supplied
	state = "in"
	needRefresh := time.Until(claims.ExpiresAt.Time) < configuration.TokenRefresh
	// jwt can be extended
	if needRefresh {
		log.Printf("handler: new jwt for: %s", ip)
		if err = CreateJwt(&w, claims); err != nil {
			log.Fatalf("handler: creating jwt - %v ", err)
		}
		RenderTemplate(&w, claims, ip, http.StatusMultipleChoices, state)
		if err != nil {
			log.Fatalf("handler: error rendering template - %v", err)
		}
		return
	}

	//log.Printf("Home for: %s", ip)
	RenderTemplate(&w, claims, ip, http.StatusOK, state)
	if err != nil {
		log.Fatalf("handler: error rendering template - %v", err)
	}
}
