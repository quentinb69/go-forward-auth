package main

import (
	"errors"
	"html/template"
	"log"
	"net/http"
	"time"
)

type TemplateData struct {
	Ip       string
	Name     string
	Csrf     string
	State    string
	HttpCode int
}

// Render HTML passed in configuration
func RenderTemplate(w *http.ResponseWriter, ctx *TemplateData, cookie *http.Cookie) error {

	if w == nil {
		return errors.New("handler: responsewriter is mandatory")
	}

	data := make(map[string]string)
	data["ip"] = ctx.Ip
	data["csrf"] = ctx.Csrf
	data["state"] = ctx.State
	data["username"] = ctx.Name

	// set headers
	if cookie != nil {
		http.SetCookie(*w, cookie)
	}
	if ctx.Name != "" {
		(*w).Header().Add("Remote-User", ctx.Name)
	}
	(*w).WriteHeader(ctx.HttpCode)

	// load template
	parsedTemplate, _ := template.ParseFiles(configuration.HtmlFile)
	// return http code and html
	return parsedTemplate.Execute(*w, data)
}

// LOGOUT HANDLER
// return 401 if not logged in
// return 302 if diconnected
func Logout(w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)

	// get valid claims
	if _, err := GetValidClaimsFromRequest(r, ip); err != nil {
		log.Printf("handler: invalid jwt claims for %s\n\t-> %v", ip, err)
		time.Sleep(500 * time.Millisecond)
		http.Redirect(w, r, "/", http.StatusUnauthorized)
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
	log.Printf("handler: logout for %s", ip)
	http.Redirect(w, r, "/", http.StatusFound)
}

// DEFAULT HANDLER
func Home(w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)
	ctx := &TemplateData{Ip: ip, State: "out", Csrf: "TODO", HttpCode: 401}

	c, err := GetValidClaimsFromRequest(r, ip)

	// no or invalid jwt supplied
	if err != nil {

		log.Printf("handler: invalid jwt for %s\n\t-> %v", ip, err)

		// invalid data supplied
		f, err := GetValidFormDataFromRequest(r, ip)
		if err != nil {
			log.Printf("handler: invalid dataform for %s\n\t-> %v", ip, err)
			// fake waiting time to limit brute force
			time.Sleep(500 * time.Millisecond)
			err = RenderTemplate(&w, ctx, nil)
			if err != nil {
				log.Fatalf("handler: error rendering template\n\t-> %v", err)
			}
			return
		}

		// invalid user
		u, err := GetValidUserFromFormData(f)
		if err != nil {
			log.Printf("handler: invalid user for %s\n\t-> %v", ip, err)
			// fake waiting time to limit brute force
			time.Sleep(500 * time.Millisecond)
			err = RenderTemplate(&w, ctx, nil)
			if err != nil {
				log.Fatalf("handler: error rendering template\n\t-> %v", err)
			}
			return
		}

		// valid data supplied
		log.Printf("handler: creating jwt for %s", ip)
		cookie, err := c.ToJwtCookie()
		if err != nil {
			log.Fatalf("handler: error creatintg jwt\n\t-> %v", err)
		}

		ctx.HttpCode = http.StatusMultipleChoices
		ctx.State = "in"
		ctx.Name = u.Name
		RenderTemplate(&w, ctx, cookie)
		if err != nil {
			log.Fatalf("handler: error rendering template\n\t-> %v", err)
		}
		return
	}

	// valid jwt supplied
	ctx.State = "in"
	needRefresh := time.Until(c.ExpiresAt.Time) < (configuration.TokenRefresh * time.Minute)
	// jwt can be extended
	if needRefresh {
		log.Printf("handler: new jwt for %s", ip)
		cookie, err := c.ToJwtCookie()
		if err != nil {
			log.Fatalf("handler: error creatintg jwt\n\t-> %v", err)
		}
		ctx.HttpCode = http.StatusMultipleChoices
		RenderTemplate(&w, ctx, cookie)
		if err != nil {
			log.Fatalf("handler: error rendering template\n\t-> %v", err)
		}
		return
	}

	ctx.HttpCode = http.StatusOK
	RenderTemplate(&w, ctx, nil)
	if err != nil {
		log.Fatalf("handler: error rendering template\n\t-> %v", err)
	}
}
