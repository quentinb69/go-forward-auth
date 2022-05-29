package main

import (
	"log"

	"github.com/knadh/koanf"
	flag "github.com/spf13/pflag"
)

var configuration *Config

// initilise configuration
func LoadConfiguration() error {
	k := koanf.New(".")
	f := flag.NewFlagSet("config", flag.ContinueOnError)

	configuration = &Config{}

	return configuration.Load(k, f)
}

func main() {
	// Load server
	if err := LoadConfiguration(); err != nil {
		log.Fatal("main: error loading configuration\n\t-> " + err.Error())
	}
	log.Fatal(LoadServer())
}
