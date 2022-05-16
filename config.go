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

// validate data, and set default values if init is true
func (c *config) Valid(init bool) error {
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
		if !init {
			return errors.New("config: bad Port")
		}
		c.Port = 8080
		log.Printf("config: setting Port to %v", c.Port)
	}
	if c.CookieName == "" {
		if !init {
			return errors.New("config: missing CookieName")
		}
		c.CookieName = "GFA"
		log.Printf("config: setting CookieName to %v", c.CookieName)
	}
	if c.TokenExpire < 1 {
		if !init {
			return errors.New("config: TokenExpire is too short")
		}
		c.TokenExpire = 90
		log.Printf("config: setting TokenExpire to %v", c.TokenExpire)
	}
	if c.TokenRefresh < 1 {
		if !init {
			return errors.New("config: TokenRefresh is too short")
		}
		c.TokenRefresh = 2
		log.Printf("config: setting TokenRefresh to %v", c.TokenRefresh)
	}
	if c.HtmlFile == "" {
		if !init {
			return errors.New("config: missing HtmlFile")
		}
		c.HtmlFile = defaultHtmlFile
		log.Printf("config: setting HtmlFile to %v", c.HtmlFile)
	}
	if _, err := os.Stat(c.HtmlFile); err != nil {
		return errors.New("config: html template error\r\t-> " + err.Error())
	}
	if len(c.JwtKey) < 32 {
		if !init {
			return errors.New("config: JwtKey is too short")
		}
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
func (c *config) LoadCommandeLine() {
	flag.StringVar(&c.ConfigurationFile, "conf", "", "Link configuration file, separated by comma.")
	flag.BoolVar(&c.Debug, "d", false, "Show configuration information in log.")
	flag.Parse()
}

// load configuration from file
func (c *config) LoadFile(k *koanf.Koanf) (isDefault bool, err error) {
	if k == nil {
		return false, errors.New("config: no koanf provided")
	}

	// if no file provided, load form default location
	isDefault = false
	if c.ConfigurationFile == "" {
		c.ConfigurationFile = defaultConfigurationFile
		isDefault = true
	}
	return isDefault, k.Load(file.Provider(c.ConfigurationFile), yaml.Parser())
}

// read configuration from file.
// If file is flag is supplied by flag load it, if not load defined arbitrary path
func LoadConfiguration() {

	var k = koanf.New(".")

	configuration.LoadCommandeLine()
	if d, err := configuration.LoadFile(k); err != nil {
		if !d {
			log.Fatalf("config: error loading file\n\t-> " + err.Error())
		}
		log.Printf("config: error loading default file\n\t-> " + err.Error())
	}

	// parse configuration in global configuration var
	if err := k.Unmarshal("", &configuration); err != nil {
		log.Fatalf("config: error parsing configuration\n\t-> %v", err)
	}

	if err := configuration.Valid(false); err != nil {
		log.Printf("config: configuration is not valid\n\t-> %v", err)
		if err := configuration.Valid(true); err != nil {
			log.Fatalf("config: default configuration is not valid either\n\t-> %v", err)
		}
	}

	log.Printf("Configuration loaded from file: %s", configuration.ConfigurationFile)

	// print configuration values
	if configuration.Debug {
		log.Printf("Configuration read:\n\t%v", k)
		log.Printf("Configuration parsed:\n\t%v", configuration)
	}
}
