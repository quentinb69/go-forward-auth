package main

import (
	"net/http"
	"time"
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
        Username string
        Ip string
	jwt.StandardClaims
}

func (c Claims) isInvalidIp(ip string) bool {
        return c.Ip != ip
}

// Create or extend jwt duration
func CreateOrExtendClaims (w *http.ResponseWriter, creds *Credentials, ip string, claims *Claims, cookie *http.Cookie ) *Claims {

        expiresAt := time.Now().Add(configuration.Expire * time.Minute)

	// create claims or extends exitent
	if claims != nil {
		claims.ExpiresAt = expiresAt.Unix()
	} else {
		claims = &Claims{
			Username: creds.Username,
			Ip: ip,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expiresAt.Unix(),
			},
		}
	}

	// jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(configuration.JwtKey)

	// add or update cookie
        http.SetCookie(*w, &http.Cookie{
                Name:    configuration.CookieName,
                Value:   tokenString,
                Expires: expiresAt,
		Domain:  configuration.CookieDomain,
		Path:    "/",
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
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return configuration.JwtKey, nil
	})

        if !token.Valid {
                return claims, cookie, errors.New("Invalid Jwt")
        }
        if err != nil {
                return claims, cookie, err
        }
        if claims.isInvalidIp(ip) {
                return claims, cookie, errors.New("Invalid IP from claims")
        }

        return claims, cookie, nil
}
