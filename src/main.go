package main

import (
	"log"
	"net/http"
)

func main() {
	loadConfiguration()
	http.HandleFunc("/", Home)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/logout", Logout)
	// start the server on port 8080
	log.Printf("Loading server on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
