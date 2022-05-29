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
	HttpReturnCode  int
	CsrfToken       string
	Ip              string
	State           string
	Url             string
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
		nil,
		nil,
		nil,
		nil,
		http.StatusInternalServerError,
		csrf.Token(r),
		GetIp(r),
		"out",
		GetHost(r),
	}

	// get jwt from cookie
	ctx.UserCookie, _ = r.Cookie(configuration.CookieName)
	cl := GetValidJwtClaims(ctx.UserCookie, ctx.Ip, ctx.Url)

	// no valid jwt (or expired, or bad domain)
	if cl == nil {
		ctx.FormData = GetFormData(r)
		ctx.User = GetValidUserFromFormData(ctx.FormData, ctx.Url)
		// no valid form data (bad credentials or bad domain)
		if ctx.User == nil {
			log.Printf("server: bad access for %s", ctx.Ip)
			time.Sleep(500 * time.Millisecond)
			ctx.HttpReturnCode = http.StatusUnauthorized
			LoadTemplate(&w, ctx)
			return
		}

		// here user is valid
		log.Printf("server: new jwt for %s", ctx.Ip)
		ctx.GeneratedCookie = CreateJwtCookie(ctx.User.Username, ctx.Ip, ctx.User.AllowedDomains)
		ctx.HttpReturnCode = http.StatusMultipleChoices
		ctx.State = "in"
		LoadTemplate(&w, ctx)
		return
	}

	ctx.FormData = GenerateFormData(cl.Subject)
	ctx.User = GetUser(cl.Subject)
	if ctx.User == nil {
		log.Printf("server: no user found for %s", ctx.Ip)
		ctx.HttpReturnCode = http.StatusUnauthorized
		// reset cookie
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
		LoadTemplate(&w, ctx)
		return
	}
	ctx.State = "in"
	ctx.HttpReturnCode = http.StatusOK
	needRefresh := time.Until(cl.ExpiresAt.Time) < (configuration.TokenRefresh * time.Minute)
	if needRefresh {
		log.Printf("server: renew jwt for %s", ctx.Ip)
		ctx.GeneratedCookie = CreateJwtCookie(ctx.User.Username, ctx.Ip, ctx.User.AllowedDomains)
		ctx.HttpReturnCode = http.StatusMultipleChoices
	}
	LoadTemplate(&w, ctx)
}

// remove cookie and redirect to home
func LogoutHandler(w http.ResponseWriter, r *http.Request) {

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
	}

	// no controle for logout but systematic sleep time
	time.Sleep(500 * time.Millisecond)

	// return to home
	http.Redirect(w, r, "/", http.StatusFound)
}

// load template and return http code and html
func LoadTemplate(w *http.ResponseWriter, ctx *Context) error {
	if w == nil || ctx == nil {
		return errors.New("server: responsewriter and context are mandatory")
	}
	if ctx.HttpReturnCode < 100 || ctx.HttpReturnCode > 599 {
		(*w).WriteHeader(http.StatusInternalServerError)
		return errors.New("server: bad http return code")
	}
	if ctx.GeneratedCookie != nil {
		http.SetCookie(*w, ctx.GeneratedCookie)
	}
	if ctx.State == "in" {
		(*w).Header().Add("Remote-User", ctx.User.Name)
	}
	(*w).WriteHeader(ctx.HttpReturnCode)
	tplData := ctx.ToMap()
	// load template
	parsedTemplate, _ := template.ParseFiles(configuration.HtmlFile)
	// return http code and html
	return parsedTemplate.Execute(*w, tplData)
}

func (ctx *Context) ToMap() map[string]interface{} {
	username := ""
	if ctx.User != nil {
		username = ctx.User.Name
	}
	if username == "" && ctx.FormData != nil {
		username = ctx.FormData.Username
	}

	return map[string]interface{}{
		"username": username,
		"state":    ctx.State,
		"csrf":     ctx.CsrfToken,
		"ip":       ctx.Ip,
	}
}
