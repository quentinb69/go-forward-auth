package main

import (
	"net/http"
	"time"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
        Username string
        Ip string
	jwt.StandardClaims
}

func (c Claims) IsInvalidIp(ip string) bool {
        return c.Ip != ip
}

// Create or extend jwt duration
func CreateOrExtendJwt (w *http.ResponseWriter, creds *Credentials, ip string, claims *Claims, cookie *http.Cookie ) *Claims {

        expiresAt := time.Now().Add(configuration.TokenExpire * time.Minute)

	// update claims
	if claims != nil {
		claims.ExpiresAt = expiresAt.Unix()
		claims.IssuedAt  = time.Now().Unix()
		claims.NotBefore = time.Now().Unix()
		claims.Ip       = ip
	// create claims
	} else {
		claims = &Claims{
			Username: creds.Username,
			Ip: ip,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expiresAt.Unix(),
				Issuer:    "gfa",
				Audience:  "https://"+configuration.CookieDomain,
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

	return claims
}

// Get Claims from request
func GetClaims (r *http.Request, ip string) (*Claims, *http.Cookie, error) {

	claims := &Claims{}

        // get token
        cookie, err := r.Cookie(configuration.CookieName)
        if err != nil {
                return nil, cookie, err
        }
        tokenString := cookie.Value

	// parse jwt to Claims
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// validate alg
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Claims : Unexpected signing method: %v", token.Header["alg"])
		}
		return configuration.JwtKey, nil
	})

        if err != nil || !token.Valid {
                return claims, cookie, errors.New("Claims : Invalid Jwt")
        }
        if err != nil {
                return claims, cookie, err
        }
        if claims.IsInvalidIp(ip) {
                return claims, cookie, errors.New("Claims : Invalid IP from claims")
        }

        return claims, cookie, nil
}
