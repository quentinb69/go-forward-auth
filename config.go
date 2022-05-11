package main

import (
	"flag"
	"log"
	"time"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
)

type config struct {
	Tls          bool              `koanf:"Tls"`
	PrivateKey   string            `koanf:"PrivateKey"`
	Cert         string            `koanf:"Cert"`
	Port         uint              `koanf:"Port"`
	CookieDomain string            `koanf:"CookieDomain"`
	CookieName   string            `koanf:"CookieName"`
	TokenExpire  time.Duration     `koanf:"TokenExpire"`
	TokenRefresh time.Duration     `koanf:"TokenRefresh"`
	HtmlFile     string            `koanf:"HtmlFile"`
	JwtKey       []byte            `koanf:"JwtKey"`
	HashCost     int               `koanf:"HashCost"`
	Users        map[string]string `koanf:"Users"`
}

const defaultConfigurationFile = "default.config.yml"
const arbitraryDefinedConfigFile = "/opt/data/config.yml"

var configuration config

func loadConfiguration() {

	// read configuration file from command line
	var k = koanf.New(".")
	var configFile string
	var debug bool
	flag.StringVar(&configFile, "conf", "", "Link configuration file.")
	flag.BoolVar(&debug, "d", false, "Show configuration information in log.")
	flag.Parse()

	// default configuration
	if err := k.Load(file.Provider(defaultConfigurationFile), yaml.Parser()); err != nil {
		log.Fatalf("Error loading default configuration\n\t-> %v", err)
	}

	// read configuration from file.
	// If file is flag is supplied by flag load it, if not load defined arbitrary path
	if configFile != "" {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			// error in supplied file, so bloking error
			log.Fatalf("Error loading configuration file\n\t-> %v", err)
		}
	} else {
		if err := k.Load(file.Provider(arbitraryDefinedConfigFile), yaml.Parser()); err != nil {
			// error in arbitrary path file, so non-bloking error
			log.Printf("Can't load configuration file\n\t-> %v", err)
		}
	}

	// load configuration in global configuration var
	if err := k.Unmarshal("", &configuration); err != nil {
		log.Fatalf("Error parsing configuration\n\t-> %v", err)
	}

	// if weak secret provided, generate one
	if len(configuration.JwtKey) < 32 {
		log.Printf("JwtKey provided is too weak (%d), generating one...", len(configuration.JwtKey))
		array, err := GenerateRand(64)
		if err != nil {
			log.Fatalf("Error generating JwtKey\n\t-> %v", err)
		}
		configuration.JwtKey = *array
	}

	log.Printf("Configuration loaded from file:\n\t%s,\n\t%s", defaultConfigurationFile, configFile)

	// print configuration values
	if debug {
		log.Printf("Configuration read:\n\t%v", k)
		log.Printf("Configuration parsed:\n\t%v", configuration)
	}
}
