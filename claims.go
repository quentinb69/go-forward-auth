package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	Username string
	Ip       string
	jwt.StandardClaims
}

func (c Claims) IsValidIp(ip string) bool {
	return c.Ip == ip
}

// Create or extend jwt duration
func CreateOrExtendJwt(w *http.ResponseWriter, creds *Credentials, ip string, claims *Claims, cookie *http.Cookie) (*Claims, error) {

	if w == nil {
		return nil, errors.New("Claims: No ResponseWriter supplied")
	}
	if creds == nil && claims == nil {
		return nil, errors.New("Claims: No claims nor credential supplied")
	}

	expiresAt := time.Now().Add(configuration.TokenExpire * time.Minute)

	// update claims
	if claims != nil {
		claims.ExpiresAt = expiresAt.Unix()
		claims.IssuedAt = time.Now().Unix()
		claims.NotBefore = time.Now().Unix()
		claims.Ip = ip
		// create claims
	} else {
		claims = &Claims{
			Username: creds.Username,
			Ip:       ip,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expiresAt.Unix(),
				Issuer:    "gfa",
				Audience:  "https://" + configuration.CookieDomain,
				IssuedAt:  time.Now().Unix(),
				NotBefore: time.Now().Unix(),
			},
		}
	}

	// create jwt token and sign it
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(configuration.JwtKey)

	// add or update cookie
	http.SetCookie(*w, &http.Cookie{
		Name:     configuration.CookieName,
		Value:    tokenString,
		Expires:  expiresAt,
		Domain:   configuration.CookieDomain,
		MaxAge:   int(configuration.TokenExpire) * 60,
		Secure:   configuration.Tls,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return claims, nil
}

// Get Claims from request
func GetClaims(r *http.Request, ip string) (*Claims, *http.Cookie, error) {

	if r == nil {
		return nil, nil, errors.New("Claims : Invalid Request")
	}

	// get token
	cookie, err := r.Cookie(configuration.CookieName)
	if err != nil {
		return nil, cookie, err
	}
	tokenString := cookie.Value

	// parse jwt to Claims
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// validate alg
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return configuration.JwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, cookie, errors.New("Claims : Invalid Jwt - " + err.Error())
	}
	if !claims.IsValidIp(ip) {
		return nil, cookie, errors.New("Claims : Invalid IP")
	}

	return claims, cookie, nil
}
