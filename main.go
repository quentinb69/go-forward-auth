package main

import (
	"log"
	"net/http"
	"fmt"
)

func main() {

	loadConfiguration()

	http.HandleFunc("/", Home)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/logout", Logout)

	log.Printf("Loading server on port %d... (TLS connection is set to %t)", configuration.Port, configuration.Tls)

	// transform PORT from int to string like ":<port>"
	var port = ":"+fmt.Sprint(configuration.Port)
	if ! configuration.Tls {
		log.Fatal(http.ListenAndServe(port, nil))
	} else {
		log.Fatal(http.ListenAndServeTLS(port, configuration.Cert, configuration.PrivateKey, nil))
	}
}