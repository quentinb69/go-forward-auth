package main

import (
	"log"
	"net/http"
	"strconv"
)

func main() {

	loadConfiguration()

	http.HandleFunc("/", Home)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/logout", Logout)

	log.Printf("Loading server on port %d. Set HTTPS to %t", configuration.Port, configuration.Tls)
	// transform PORT from int to string like ":<port>"
	var port = ":"+strconv.Itoa(configuration.Port)
	if ! configuration.Tls {
		log.Fatal(http.ListenAndServe(port, nil))
	} else {
		log.Fatal(http.ListenAndServeTLS(port, configuration.Cert, configuration.PrivateKey, nil))
	}
}
