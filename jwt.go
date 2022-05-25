package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	Name        string
	Ip          string
	IsAdmin     bool
	Domains     []string
	customValid bool
	jwt.RegisteredClaims
}

// check if claims is legit
func (c *Claims) CustomValid(ip string) error {
	if c == nil {
		return errors.New("jwt: no claims supplied")
	}

	c.customValid = false
	if err := c.Valid(); err != nil {
		return err
	}
	if c.Ip != ip {
		return errors.New("jwt: ip doesn't match")
	}
	c.customValid = true
	return nil
}

// Create claims from User
// return an error if critic parameters are nil
func GetClaimsFromUser(u *User, ip string) (c *Claims, err error) {

	if u == nil {
		return nil, errors.New("jwt: no user supplied")
	}
	if ip == "" {
		return nil, errors.New("jwt: no ip provided")
	}
	// uniq id
	id, err := GenerateRand(30)
	if err != nil {
		return nil, errors.New("jwt: error generating claims id\n\t-> " + err.Error())
	}

	c = &Claims{
		// Custom Claims
		Name:    u.Name,
		Ip:      ip,
		IsAdmin: u.IsAdmin,
		Domains: u.AllowedDomains,
		// Registered Claims
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.Id,
			ID:        base64.URLEncoding.EncodeToString(*id),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(configuration.TokenExpire * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "GFA",
			Audience:  jwt.ClaimStrings{"https://" + configuration.CookieDomain},
		},
	}

	return c, nil
}

// Create jwt from claims
// return an error if critic parameters are nil
func (c *Claims) ToJwtCookie() (cookie *http.Cookie, err error) {

	if c == nil {
		return nil, errors.New("jwt: no claims supplied")
	}
	if c.Subject == "" || c.Ip == "" || c.ID == "" || (!c.IsAdmin && len(c.Domains) == 0) {
		return nil, errors.New("jwt: missing username or ip or id or allowed website")
	}
	if err = c.Valid(); err != nil {
		return nil, errors.New("jwt: invalid\n\t-> " + err.Error())
	}

	// Create jwt token and sign it
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	tokenString, _ := token.SignedString(configuration.JwtSecretKey)

	// Add or update cookie
	return &http.Cookie{
		Name:     configuration.CookieName,
		Value:    tokenString,
		Expires:  c.ExpiresAt.Time,
		Domain:   configuration.CookieDomain,
		MaxAge:   int(configuration.TokenExpire * time.Minute),
		Secure:   configuration.Tls,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// Create claims from request
// return an error if JWT is invalid or inexistant
func GetValidClaimsFromRequest(r *http.Request, ip string) (c *Claims, err error) {

	if r == nil {
		return nil, errors.New("jwt: no request provided")
	}

	// Get cookie
	cookie, err := r.Cookie(configuration.CookieName)
	if err != nil {
		return nil, errors.New("jwt: no cookie provided")
	}

	// Get token
	c = &Claims{}
	tokenString := cookie.Value

	// Parse jwt to Claims
	token, err := jwt.ParseWithClaims(tokenString, c, func(token *jwt.Token) (interface{}, error) {
		// Validate alg for security ("none" is not allowed)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return configuration.JwtSecretKey, nil
	})

	// Validate jwt
	if err != nil || !token.Valid {
		return nil, errors.New("jwt: invalid\n\t-> " + err.Error())
	}
	// Custom validation
	return c, c.CustomValid(ip)
}
