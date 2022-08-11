package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
)

type Claims struct {
	Ip string
	jwt.RegisteredClaims
}

// check if claims is legit
func ValidateClaims(c *Claims, ip, url string) (err error) {
	if c == nil {
		return errors.New("jwt: no claims supplied")
	}
	if c.Subject == "" || c.Ip == "" || c.ID == "" {
		return errors.New("jwt: missing username or ip or id")
	}
	// Check if ip is allowed
	if c.Ip != configuration.MagicIp && (ip == "" || c.Ip != ip) {
		return errors.New("jwt: ip doesn't match")
	}
	// Check if domains is allowed
	if url == "" || !CompareDomains(c.Audience, url) {
		return errors.New("jwt: domain not allowed")
	}
	// Check if claims is valid
	return c.Valid()
}

// Create claims from User
// return an error if critic parameters are nil
func CreateJwtCookie(username, ip string, domains []string) *http.Cookie {

	// uniq id
	id := GenerateRandomBytes(30)
	if len(*id) == 0 {
		log.Error("jwt: failed to generate random bytes")
		return nil
	}

	cl := &Claims{
		// custom Claims
		Ip: ip,
		// registered Claims
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ID:        base64.URLEncoding.EncodeToString(*id),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(configuration.TokenExpire * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "GFA",
			Audience:  domains,
		},
	}

	// create jwt token and sign it
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	tokenString, _ := token.SignedString(configuration.JwtSecretKey)
	// return Cookie
	return &http.Cookie{
		Name:     configuration.CookieName,
		Value:    tokenString,
		Expires:  cl.ExpiresAt.Time,
		Domain:   configuration.CookieDomain,
		MaxAge:   int(configuration.TokenExpire * time.Minute),
		Secure:   configuration.Tls,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// Get claims from request
// return nil if claims is invalid
func GetValidJwtClaims(c *http.Cookie, ip, url string) (cl *Claims) {

	if c == nil {
		log.Info("jwt: no cookie", zap.String("ip", ip))
		return nil
	}

	// Get token
	cl = &Claims{}
	tokenString := c.Value

	// Parse jwt to Claims
	token, err := jwt.ParseWithClaims(tokenString, cl, func(token *jwt.Token) (interface{}, error) {
		// Validate alg for security ("none" is not allowed)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return configuration.JwtSecretKey, nil
	})

	// Validate jwt
	if err != nil || !token.Valid {
		log.Error("jwt: invalid claims", zap.String("ip", ip), zap.Error(err))
		return nil
	}
	// Custom validation
	if err := ValidateClaims(cl, ip, url); err != nil {
		log.Error("jwt: invalid claims", zap.String("ip", ip), zap.Error(err))
		return nil
	}

	return cl
}
