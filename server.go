package main

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/gorilla/csrf"
	"go.uber.org/zap"
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
		csrf.Secure(true),
		csrf.Path("/"),
		csrf.CookieName(configuration.CookieName+"_csrf"),
		csrf.Domain(configuration.CookieDomain),
	)

	r := http.NewServeMux()
	r.HandleFunc("/", ShowHomeHandler)
	r.HandleFunc("/verify", VerifyHandler)
	r.HandleFunc("/logout", LogoutHandler)
	r.HandleFunc("/health", HealthHandler)

	log.Info("Loading server...", zap.Uint("port", configuration.Port))

	// transform PORT from int to string like ":<port>"
	var port = ":" + fmt.Sprint(configuration.Port)
	return http.ListenAndServeTLS(port, configuration.Certificate, configuration.PrivateKey, CSRF(r))
}

// health handler
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte("OK"))
}

// default handler
func ShowHomeHandler(w http.ResponseWriter, r *http.Request) {

	// Init ctx
	ctx := &Context{
		CsrfToken: csrf.Token(r),
		Ip:        GetIp(r),
		State:     "out",
		Url:       GetHost(r),
	}

	log.Sugar().Debug("server: home requested", zap.String("ip", ctx.Ip), "request", r)

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
				log.Error("server: bad token", zap.String("ip", ctx.Ip))
				ctx.HttpReturnCode = http.StatusForbidden
				ctx.State = "out"
				// if cookie is still valid, it means the user is trying to access an unauthorized Domain
				if err := ctx.UserCookie.Valid(); err == nil {
					ctx.ErrorMessage = "Unauthorized access"
				}
			}
			log.Info("Loading Template", zap.Int("status", ctx.HttpReturnCode), zap.Error(LoadTemplate(&w, ctx)))
			return
		}

		// from here formdata is provided
		ctx.User = GetValidUserFromFormData(ctx.FormData, ctx.Url)

		switch {
		// bad credentials
		case ctx.User == nil:
			time.Sleep(500 * time.Millisecond)
			ctx.HttpReturnCode = http.StatusUnauthorized
			ctx.State = "out"
			ctx.ErrorMessage = "Bad credentials"
		// data provided are valid
		case ctx.User != nil:
			log.Info("server: new jwt", zap.String("ip", ctx.Ip))
			ctx.HttpReturnCode = http.StatusMultipleChoices
			ctx.State = "in"

			// set MagicIp if user allow connection from anyip
			claimsIp := ctx.Ip
			if ctx.FormData.AnyIp {
				claimsIp = configuration.MagicIp
			}

			ctx.GeneratedCookie = CreateJwtCookie(ctx.User.Username, claimsIp, ctx.User.AllowedDomains)
		}
		log.Info("Loading Template", zap.Int("status", ctx.HttpReturnCode), zap.Error(LoadTemplate(&w, ctx)))
		return
	}

	// from here, we have a valid Jwt
	// refresh needed
	if time.Until(ctx.Claims.ExpiresAt.Time) < (configuration.TokenRefresh * time.Minute) {
		ctx.User = GetUser(ctx.Claims.Subject)
		switch {
		// bad user
		case ctx.User == nil:
			log.Error("server: user not found", zap.String("user", ctx.Claims.Subject))
			ctx.HttpReturnCode = http.StatusForbidden
			ctx.State = "out"
			ctx.GeneratedCookie = &http.Cookie{
				Name:     configuration.CookieName,
				Value:    "",
				Expires:  time.Now(),
				Domain:   configuration.CookieDomain,
				MaxAge:   -1,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}
		// refreshed user
		case ctx.User != nil:
			log.Info("server: renew jwt", zap.String("ip", ctx.Ip))
			ctx.HttpReturnCode = http.StatusMultipleChoices
			ctx.State = "in"
			ctx.GeneratedCookie = CreateJwtCookie(ctx.User.Username, ctx.Ip, ctx.User.AllowedDomains)
			// validate new cookie domain is allowed
			if GetValidJwtClaims(ctx.GeneratedCookie, ctx.Ip, ctx.Url) == nil {
				ctx.ErrorMessage = "Restricted Area"
			}
		}
		log.Info("Loading Template", zap.Int("status", ctx.HttpReturnCode), zap.Error(LoadTemplate(&w, ctx)))
		return
	}
	// all validations passed
	ctx.HttpReturnCode = http.StatusOK
	ctx.State = "in"
	log.Debug("Loading Template", zap.Int("status", ctx.HttpReturnCode), zap.Error(LoadTemplate(&w, ctx)))
}

// remove cookie and redirect to home
func LogoutHandler(w http.ResponseWriter, r *http.Request) {

	ip := GetIp(r)
	log.Sugar().Debug("server: logout requested", zap.String("ip", ip), "request", r)

	// remove cookie if exists
	if c, _ := r.Cookie(configuration.CookieName); c != nil {
		log.Info("server: delete jwt", zap.String("ip", ip))

		http.SetCookie(w, &http.Cookie{
			Name:     configuration.CookieName,
			Value:    "",
			Expires:  time.Now(),
			Domain:   configuration.CookieDomain,
			MaxAge:   -1,
			Secure:   true,
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

// remove cookie and redirect to home
func VerifyHandler(w http.ResponseWriter, r *http.Request) {

	// Init ctx
	ctx := &Context{
		Ip:        GetIp(r),
		Url:       GetHost(r),
	}

	log.Sugar().Debug("server: verify requested", zap.String("ip", ctx.Ip), "request", r)

	// get jwt from cookie
	ctx.UserCookie, _ = r.Cookie(configuration.CookieName)
	ctx.Claims = GetValidJwtClaims(ctx.UserCookie, ctx.Ip, ctx.Url)
	
	// if no valid claims
	if ctx.Claims == nil {
		w.WriteHeader(http.StatusForbidden)
		// no cookie, prevent bruteforce with sleeptime
		time.Sleep(500 * time.Millisecond)
	}

	w.WriteHeader(http.StatusOK)
	return
}

// load template and return http code and html
func LoadTemplate(w *http.ResponseWriter, ctx *Context) error {
	if w == nil || ctx == nil {
		return errors.New("server: responsewriter and context are mandatory")
	}

	log.Sugar().Debug("server: final context", zap.String("ip", ctx.Ip), "context", ctx)

	if ctx.HttpReturnCode < 100 || ctx.HttpReturnCode > 599 {
		(*w).WriteHeader(http.StatusNotImplemented)
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
	// parse data in template
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
