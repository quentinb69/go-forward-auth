package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/knadh/koanf"
	flag "github.com/spf13/pflag"
)

func main() {

	k := koanf.New(".")
	f := flag.NewFlagSet("config", flag.ContinueOnError)

	configuration := &Config{}

	if err := configuration.Load(k, f); err != nil {
		log.Fatal("main: error loading configuration\n\t-> " + err.Error())
	}

	http.HandleFunc("/", Home)
	http.HandleFunc("/logout", Logout)

	log.Printf("Loading server on port %d... (TLS connection is set to %t)", configuration.Port, configuration.Tls)

	// transform PORT from int to string like ":<port>"
	var port = ":" + fmt.Sprint(configuration.Port)
	if !configuration.Tls {
		log.Fatal(http.ListenAndServe(port, nil))
	} else {
		log.Fatal(http.ListenAndServeTLS(port, configuration.Certificate, configuration.PrivateKey, nil))
	}
}
