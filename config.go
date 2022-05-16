package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"os"
	"time"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
)

type config struct {
	Tls               bool              `koanf:"Tls"`
	PrivateKey        string            `koanf:"PrivateKey"`
	Cert              string            `koanf:"Cert"`
	Port              uint              `koanf:"Port"`
	CookieDomain      string            `koanf:"CookieDomain"`
	CookieName        string            `koanf:"CookieName"`
	TokenExpire       time.Duration     `koanf:"TokenExpire"`
	TokenRefresh      time.Duration     `koanf:"TokenRefresh"`
	HtmlFile          string            `koanf:"HtmlFile"`
	JwtKey            []byte            `koanf:"JwtKey"`
	HashCost          int               `koanf:"HashCost"`
	Users             map[string]string `koanf:"Users"`
	Debug             bool              `koanf:"Debug"`
	ConfigurationFile string
}

const defaultConfigurationFile = "default.config.yml"
const defaultHtmlFile = "default.index.html"

var configuration config

// validate data, and set default values
func (c *config) setValid() error {
	if c.Tls && (c.PrivateKey == "" || c.Cert == "") {
		return errors.New("config: if Tls is true, please provide PrivateKey and Cert")
	}
	if c.Tls {
		_, err := tls.LoadX509KeyPair(c.Cert, c.PrivateKey)
		if err != nil {
			return errors.New("config: bad key pair\r\t-> " + err.Error())
		}
	}
	if c.Port < 1 || c.Port > 65534 {
		c.Port = 8080
		log.Printf("config: setting Port to %v", c.Port)
	}
	if c.CookieName == "" {
		c.CookieName = "GFA"
		log.Printf("config: setting CookieName to %v", c.CookieName)
	}
	if c.TokenExpire < 1 {
		c.TokenExpire = 90
		log.Printf("config: setting TokenExpire to %v", c.TokenExpire)
	}
	if c.TokenRefresh < 1 {
		c.TokenRefresh = 2
		log.Printf("config: setting TokenRefresh to %v", c.TokenRefresh)
	}
	if c.HtmlFile == "" {
		c.HtmlFile = defaultHtmlFile
		log.Printf("config: setting HtmlFile to %v", c.HtmlFile)
	}
	if _, err := os.Stat(c.HtmlFile); err != nil {
		return errors.New("config: html template error\r\t-> " + err.Error())
	}
	if len(c.JwtKey) < 32 {
		log.Printf("config: JwtKey provided is too weak (%d), generating secure one...", len(c.JwtKey))
		array, err := GenerateRand(64)
		if err != nil {
			return errors.New("config : error generating JwtKey\n\t-> " + err.Error())
		}
		c.JwtKey = *array
	}
	return nil
}

// load configuration from command line
func LoadCommandeLineConfiguration() {
	flag.StringVar(&configuration.ConfigurationFile, "conf", "", "Link configuration file, separated by comma.")
	flag.BoolVar(&configuration.Debug, "d", false, "Show configuration information in log.")
	flag.Parse()
}

// load configuration from file
func LoadFileConfiguration(k *koanf.Koanf) (isDefault bool, err error) {
	if k == nil {
		return false, errors.New("config: no koanf provided")
	}

	// if no file provided, load form default location
	isDefault = false
	if configuration.ConfigurationFile == "" {
		configuration.ConfigurationFile = defaultConfigurationFile
		isDefault = true
	}
	return isDefault, k.Load(file.Provider(configuration.ConfigurationFile), yaml.Parser())
}

// read configuration from file.
// If file is flag is supplied by flag load it, if not load defined arbitrary path
func LoadConfiguration() {

	var k = koanf.New(".")

	LoadCommandeLineConfiguration()
	if d, err := LoadFileConfiguration(k); err != nil {
		if !d {
			log.Fatalf("config: error loading file\n\t-> " + err.Error())
		}
		log.Printf("config: error loading default file\n\t-> " + err.Error())
	}

	// parse configuration in global configuration var
	if err := k.Unmarshal("", &configuration); err != nil {
		log.Fatalf("config: error parsing configuration\n\t-> %v", err)
	}

	if err := configuration.setValid(); err != nil {
		log.Fatalf("config: configuration is not valid\n\t-> %v", err)
	}

	log.Printf("Configuration loaded from file: %s", configuration.ConfigurationFile)

	// print configuration values
	if configuration.Debug {
		log.Printf("Configuration read:\n\t%v", k)
		log.Printf("Configuration parsed:\n\t%v", configuration)
	}
}
