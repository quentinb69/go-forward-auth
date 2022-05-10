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
	Username string
	Ip       string
	jwt.RegisteredClaims
}

// compare ip with the one in claims
func (c Claims) IsValidIp(ip string) bool {
	return c.Ip == ip
}

// Create claims from credentials
// return an error if critic parameters are nil
func CreateClaims(creds *Credentials, ip string) (claims *Claims, err error) {
	if creds == nil {
		return nil, errors.New("claims: no credentials supplied")
	}
	if err = creds.IsValid(); err != nil {
		return nil, err
	}
	if ip == "" {
		return nil, errors.New("claims: no ip provided")
	}

	claims = &Claims{}
	claims.Username = creds.Username
	claims.Ip = ip

	return claims, nil
}

// Create jwt from claims
// return an error if critic parameters are nil
func CreateJwt(w *http.ResponseWriter, claims *Claims) (err error) {

	if w == nil {
		return errors.New("claims: no responsewriter supplied")
	}
	if claims == nil {
		return errors.New("claims: no claims supplied")
	}
	if claims.Username == "" || claims.Ip == "" {
		return errors.New("claims: no username nor ip in claims")
	}

	// uniq id
	id, err := GenerateRand(30)
	if err != nil {
		return errors.New("claims: error generating claims id")
	}

	// set standard claims data
	expiresAt := time.Now().Add(configuration.TokenExpire * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expiresAt)
	claims.IssuedAt = jwt.NewNumericDate(time.Now())
	claims.NotBefore = jwt.NewNumericDate(time.Now())
	claims.RegisteredClaims =
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Issuer:    "gfa",
			Audience:  jwt.ClaimStrings{"https://" + configuration.CookieDomain},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        base64.URLEncoding.EncodeToString(*id),
		}

	// Create jwt token and sign it
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(configuration.JwtKey)
	fmt.Printf("TEST: %v", tokenString)

	// Add or update cookie
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

	return nil
}

// Get Claims from request
// return an error if JWT is invalid or inexistant
func GetClaims(r *http.Request, ip string) (claims *Claims, err error) {

	if r == nil {
		return nil, errors.New("claims: invalid request")
	}

	// Get token
	cookie, err := r.Cookie(configuration.CookieName)
	if err != nil {
		return nil, err
	}
	tokenString := cookie.Value

	// Parse jwt to Claims
	claims = &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Validate alg for security ("none" is not allowed)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return configuration.JwtKey, nil
	})

	// Validate jwt
	if err != nil || !token.Valid {
		return nil, errors.New("claims: invalid jwt - " + err.Error())
	}
	// Validate ip
	if !claims.IsValidIp(ip) {
		return nil, errors.New("claims: invalid ip")
	}

	return claims, nil
}
