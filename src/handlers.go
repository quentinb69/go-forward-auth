package main

import (
	"net/http"
	"html/template"
	"time"
	"log"
	"bytes"
	"image"
	"image/gif"
	"strconv"
)

// Return HTML
func RenderTemplate (w *http.ResponseWriter, claims *Claims, ip string, httpCode int, state string) {

	data := make(map[string]string)
	data["ip"] = ip
	data["csrf"] = "TODO"
	data["state"] = state

	// Login ok
	if claims != nil {
		data["username"] = claims.Username
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
// return 302 if not logged in
// return 200 if diconnected
func Logout(w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)
	_, _, err := GetClaims (r, ip)

	// return 401
	if err != nil {
		log.Printf("Failed attempt for: %s", ip)
		log.Printf("Claims error: %s", err)
		time.Sleep(500 * time.Millisecond)
		http.Redirect(w, r, "/", 302)
		return
	}

	// remove cookie
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
// return 302 if login ok
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

        CreateOrExtendClaims(&w, credentials, ip, nil, nil)

	// return 200
	log.Printf("Login for: %s", ip)
	http.Redirect(w, r, "/", http.StatusOK)
        return
}

// DEFAULT HANDLER
func Home (w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)
	claims, cookie, errClaims := GetClaims (r, ip)
	credentials, errCredentials := GetCredentials (r)
        state:= "out"

	// no valid claims and no credentials submitted
	if errClaims != nil && errCredentials != nil {
		log.Printf("Failed attempt for: %s", ip)
		log.Printf("Claims error: %v", errClaims)
		log.Printf("Credentials error: %v", errCredentials)
		time.Sleep(500 * time.Millisecond)
		RenderTemplate(&w, claims, ip, http.StatusUnauthorized, state)
		return
	}

	// now we are allowed
	state = "in"

	// credentials supplied
	if errCredentials == nil {
		log.Printf("Create claims for: %s", ip)
		CreateOrExtendClaims(&w, credentials, ip, claims, cookie)
		RenderTemplate(&w, claims, ip, 300, state)
		return
	}

	// claims exists and need to be extended
	if errClaims == nil && time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) < 1*time.Minute {
		log.Printf("Refresh claims for: %s", ip)
		CreateOrExtendClaims(&w, credentials, ip, claims, cookie)
		RenderTemplate(&w, claims, ip, 300, state)
		return
	}

	//log.Printf("Home for: %s", ip)
	RenderTemplate(&w, claims, ip, http.StatusOK, state)
	return
}

// return abrotrary designed favicon
func Favicon (w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	gif.Encode(&buf, image.Rect(4, 4, 12, 12), nil)

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Length", strconv.Itoa(len(buf.Bytes())))
	w.Write(buf.Bytes())

	return
}
