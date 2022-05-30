package main

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/csrf"
)

type Context struct {
	FormData        *FormData
	User            *User
	UserCookie      *http.Cookie
	GeneratedCookie *http.Cookie
	Claims          *Claims
	HttpReturnCode  int
	CsrfToken       string
	Ip              string
	State           string
	Url             string
	ErrorMessage    string
}

// set handler for and start listening
func LoadServer() error {

	CSRF := csrf.Protect(
		[]byte(configuration.CsrfSecretKey),
		csrf.Secure(configuration.Tls),
		csrf.Path("/"),
		csrf.CookieName(configuration.CookieName+"_csrf"),
		csrf.Domain(configuration.CookieDomain),
	)

	r := http.NewServeMux()
	r.HandleFunc("/", ShowHomeHandler)
	r.HandleFunc("/logout", LogoutHandler)

	log.Printf("Loading server on port %d... (TLS connection is set to %t)", configuration.Port, configuration.Tls)

	// transform PORT from int to string like ":<port>"
	var port = ":" + fmt.Sprint(configuration.Port)
	if !configuration.Tls {
		return http.ListenAndServe(port, CSRF(r))
	} else {
		return http.ListenAndServeTLS(port, configuration.Certificate, configuration.PrivateKey, CSRF(r))
	}
}

// default handler
func ShowHomeHandler(w http.ResponseWriter, r *http.Request) {

	// Init ctx
	ctx := &Context{
		HttpReturnCode: http.StatusInternalServerError,
		CsrfToken:      csrf.Token(r),
		Ip:             GetIp(r),
		State:          "out",
		Url:            GetHost(r),
	}

	if configuration.Debug {
		log.Printf("server: home request for %s\n\t-> %v", ctx.Ip, r)
	}

	if configuration.Debug {
		log.Printf("server: home request for %s\n\t-> %v", ctx.Ip, r)
	}

	// get jwt from cookie
	ctx.UserCookie, _ = r.Cookie(configuration.CookieName)
	ctx.Claims = GetValidJwtClaims(ctx.UserCookie, ctx.Ip, ctx.Url)

	// no valid jwt (or expired, or bad domain)
	if ctx.Claims == nil {

		ctx.FormData = GetFormData(r)

		if ctx.FormData == nil {
			switch {
			// first access (no form nor cookie)
			case ctx.UserCookie == nil:
				ctx.HttpReturnCode = http.StatusUnauthorized
				ctx.State = "out"
			// bad domain (only cookie)
			case ctx.UserCookie != nil:
				log.Printf("server: bad domain for %s", ctx.Ip)
				ctx.HttpReturnCode = http.StatusForbidden
				ctx.State = "out"
				ctx.ErrorMessage = "Restricted Area"
			}
			LoadTemplate(&w, ctx)
			return
		}

		// here form data is provided
		ctx.User = GetValidUserFromFormData(ctx.FormData, ctx.Url)

		switch {
		// bad credentials
		case ctx.User == nil:
			time.Sleep(500 * time.Millisecond)
			ctx.HttpReturnCode = http.StatusUnauthorized
			ctx.State = "out"
			ctx.ErrorMessage = "Bad credentials"
		// data provided ar valid
		case ctx.User != nil:
			log.Printf("server: new jwt for %s", ctx.Ip)
			ctx.HttpReturnCode = http.StatusFound
			ctx.State = "in"
			ctx.GeneratedCookie = CreateJwtCookie(ctx.User.Username, ctx.Ip, ctx.User.AllowedDomains)

		}
		LoadTemplate(&w, ctx)
		return
	}

	// if we are here, we should have a valid Jwt
	needRefresh := time.Until(ctx.Claims.ExpiresAt.Time) < (configuration.TokenRefresh * time.Minute)

	// refresh needed
	if needRefresh {
		u := GetUser(ctx.Claims.Subject)
		switch {
		// bad user
		case u == nil:
			log.Printf("server: user %s not found", ctx.Claims.Subject)
			ctx.HttpReturnCode = http.StatusForbidden
			ctx.State = "out"
			ctx.GeneratedCookie = &http.Cookie{
				Name:     configuration.CookieName,
				Value:    "",
				Expires:  time.Now(),
				Domain:   configuration.CookieDomain,
				MaxAge:   -1,
				Secure:   configuration.Tls,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}
		// refreshed user
		case u != nil:
			log.Printf("server: renew jwt for %s", ctx.Ip)
			ctx.HttpReturnCode = http.StatusFound
			ctx.State = "in"
			ctx.GeneratedCookie = CreateJwtCookie(ctx.Claims.Subject, ctx.Claims.Ip, ctx.Claims.Audience)
			// validate new cookie domain is alllowed
			if GetValidJwtClaims(ctx.GeneratedCookie, ctx.Ip, ctx.Url) == nil {
				ctx.HttpReturnCode = http.StatusForbidden
				ctx.State = "in"
				ctx.ErrorMessage = "Restricted Area"
			}
		}
		LoadTemplate(&w, ctx)
		return
	}
	// all validations passed, we can load the template
	ctx.HttpReturnCode = http.StatusOK
	ctx.State = "in"
	LoadTemplate(&w, ctx)
}

// remove cookie and redirect to home
func LogoutHandler(w http.ResponseWriter, r *http.Request) {

	if configuration.Debug {
		log.Printf("server: logout request for %s\n\t-> %v", GetIp(r), r)
	}

	// remove cookie if exists
	if c, _ := r.Cookie(configuration.CookieName); c != nil {
		ip := GetIp(r)
		log.Printf("server: delete jwt for %s", ip)
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
	} else {
		// no cookie, prevent bruteforce with sleeptime
		time.Sleep(500 * time.Millisecond)
	}

	// return to home
	http.Redirect(w, r, "/", http.StatusFound)
}

// load template and return http code and html
func LoadTemplate(w *http.ResponseWriter, ctx *Context) error {
	if w == nil || ctx == nil {
		return errors.New("server: responsewriter and context are mandatory")
	}
	if configuration.Debug {
		log.Printf("server: final context for %s\n\t-> %v", ctx.Ip, ctx)
	}
	if ctx.HttpReturnCode < 100 || ctx.HttpReturnCode > 599 {
		(*w).WriteHeader(http.StatusInternalServerError)
		return errors.New("server: bad http return code")
	}
	if ctx.GeneratedCookie != nil {
		http.SetCookie(*w, ctx.GeneratedCookie)
	}
	if ctx.State == "in" {
		(*w).Header().Add("Remote-User", ctx.GetUsername())
	}
	(*w).WriteHeader(ctx.HttpReturnCode)
	tplData := ctx.ToMap()
	// load template
	parsedTemplate, _ := template.ParseFiles(configuration.HtmlFile)
	// return http code and html
	return parsedTemplate.Execute(*w, tplData)
}

func (ctx *Context) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"username": ctx.GetUsername(),
		"state":    ctx.State,
		"csrf":     ctx.CsrfToken,
		"ip":       ctx.Ip,
		"error":    ctx.ErrorMessage,
	}
}

func (ctx *Context) GetUsername() string {
	switch {
	case ctx.User != nil:
		return ctx.User.Username
	case ctx.Claims != nil:
		return ctx.Claims.Subject
	case ctx.FormData != nil:
		return ctx.FormData.Username
	default:
		return ""
	}
}
