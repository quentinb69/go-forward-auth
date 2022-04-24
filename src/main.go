package main

import (
	"log"
	"net/http"
	"strconv"
)

func main() {
	loadConfiguration()
	http.HandleFunc("/", Home)
	http.HandleFunc("/favicon.ico", Favicon)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/logout", Logout)
	// start the server on port 8080
	log.Printf("Loading server on port %d", configuration.Port)
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(configuration.Port), nil))
}
