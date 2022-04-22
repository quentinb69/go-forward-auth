package main

import (
	"log"
	"time"
	"flag"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
)

type config struct {
	CookieDomain	string			`koanf:"CookieDomain"`
	CookieName	string			`koanf:"CookieName"`
	Expire		time.Duration		`koanf:"Expire"`
	HtmlFile	string			`koanf:"HtmlFile"`
	JwtKey		[]byte			`koanf:"JwtKey"`
	Users		map[string]string	`koanf:"Users"`
}

const defaultConfigurationFile = "/data/config.yml"
var k = koanf.New(".")
var configuration config

func loadConfiguration() {

	// read configuration file from command line
	var configFile string
	flag.StringVar(&configFile, "conf", defaultConfigurationFile, "Link configuration file.")
	flag.Parse()

	// read configuration from file
	if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
		log.Fatalf("Error loading configuration file: %v", err)
	}

	// load configuration in global var
	if err := k.Unmarshal("", &configuration); err != nil {
		log.Fatalf("Error parsing configuration: %v", err)
	}

	log.Printf("Configuration loaded from file: %s", configFile)
	return
}
