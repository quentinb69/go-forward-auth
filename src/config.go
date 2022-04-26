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
	Tls		bool			`koanf:"Tls"`
	PrivateKey	string			`koanf:"PrivateKey"`
	Cert		string			`koanf:"Cert"`
	Port		int			`koanf:"Port"`
	CookieDomain	string			`koanf:"CookieDomain"`
	CookieName	string			`koanf:"CookieName"`
	Expire		time.Duration		`koanf:"Expire"`
	HtmlFile	string			`koanf:"HtmlFile"`
	JwtKey		[]byte			`koanf:"JwtKey"`
	HashCost	int			`koanf:"HashCost"`
	Users		map[string]string	`koanf:"Users"`
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
	if err :=  k.Load(file.Provider(defaultConfigurationFile), yaml.Parser()); err != nil {
	        log.Fatalf("Error loading default configuration: %v", err)
        }

	// read configuration from file.
	// If file is flag is supplied by flag load it, if not load defined arbitrary path
	if configFile != "" {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			// error in supplied file, so bloking error
			log.Fatalf("Error loading configuration file: %v", err)
		}
	} else {
		if err := k.Load(file.Provider(arbitraryDefinedConfigFile), yaml.Parser()); err != nil {
			// error in arbitrary path file, so non-bloking error
			log.Printf("Can't load configuration file: %v", err)
                }
	}

	// load configuration in global configuration var
	if err := k.Unmarshal("", &configuration); err != nil {
		log.Fatalf("Error parsing configuration: %v", err)
	}

	log.Printf("Configuration loaded from file: %s, %s", defaultConfigurationFile, configFile)

	// print configuration values
	if debug {
		log.Printf("Configuration read: %v", k)
		log.Printf("Configuration parsed: %v", configuration)
	}

	return
}
