package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	flag "github.com/spf13/pflag" // POSIX compliant

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
)

type Config struct {
	Tls               bool            `koanf:"Tls"`
	PrivateKey        string          `koanf:"PrivateKey"`
	Certificate       string          `koanf:"Certificate"`
	Port              uint            `koanf:"Port"`
	CookieDomain      string          `koanf:"CookieDomain"`
	CookieName        string          `koanf:"CookieName"`
	TokenExpire       time.Duration   `koanf:"TokenExpire"`
	TokenRefresh      time.Duration   `koanf:"TokenRefresh"`
	HtmlFile          string          `koanf:"HtmlFile"`
	JwtSecretKey      []byte          `koanf:"JwtSecretKey"`
	HashCost          int             `koanf:"HashCost"`
	Debug             bool            `koanf:"Debug"`
	Users             map[string]User `koanf:"Users"`
	ConfigurationFile []string
}

const defaultConfigurationFile = "default.config.yml"
const defaultHtmlFile = "default.index.html"

var configuration *Config

// validate data, and set default values if init is true
func (c *Config) Valid(init bool) error {
	if c == nil {
		return errors.New("config: no configuration provided")
	}

	if c.Tls {
		_, err := tls.LoadX509KeyPair(c.Certificate, c.PrivateKey)
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
			return errors.New("config: TokenExpire is too small")
		}
		c.TokenExpire = 90
		log.Printf("config: setting TokenExpire to %v", c.TokenExpire)
	}
	if c.TokenRefresh < 1 {
		if !init {
			return errors.New("config: TokenRefresh is too small")
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
	if len(c.JwtSecretKey) < 32 {
		if !init {
			return errors.New("config: JwtSecretKey is too small")
		}
		log.Printf("config: JwtSecretKey provided is too weak (%d), generating secure one...", len(c.JwtSecretKey))
		array, err := GenerateRand(64)
		if err != nil {
			return errors.New("config : error generating JwtSecretKey\n\t-> " + err.Error())
		}
		c.JwtSecretKey = *array
	}
	return nil
}

// load configuration from command line
func (c *Config) LoadCommandeLine(f *flag.FlagSet) error {
	if c == nil {
		return errors.New("config: no configuration provided")
	}

	f.Usage = func() {
		fmt.Println(f.FlagUsages())
		os.Exit(0)
	}

	if !f.HasFlags() {
		f.StringSlice("conf", c.ConfigurationFile, "Link to one or more configurations files.")
		f.Bool("d", c.Debug, "Enable some debbug log.")
	}

	f.Parse(os.Args[1:])

	c.Debug, _ = f.GetBool("d")
	c.ConfigurationFile, _ = f.GetStringSlice("conf")

	return nil
}

// load configuration from file
func (c *Config) LoadFile(k *koanf.Koanf) (isDefault bool, err error) {
	if k == nil || c == nil {
		return false, errors.New("config: no koanf nor configuration provided")
	}

	// if no file provided, load form default location
	isDefault = false
	if len(c.ConfigurationFile) == 0 {
		c.ConfigurationFile = []string{defaultConfigurationFile}
		isDefault = true
	}

	for _, f := range c.ConfigurationFile {
		if err := k.Load(file.Provider(f), yaml.Parser()); err != nil {
			return isDefault, err
		}
	}
	return isDefault, nil
}

// read configuration from file.
// If file is flag is supplied by flag load it, if not load defined arbitrary path
func (c *Config) Load(k *koanf.Koanf, f *flag.FlagSet) (err error) {
	if c == nil {
		return errors.New("config: no configuration provided")
	}

	if err := c.LoadCommandeLine(f); err != nil {
		return errors.New("config: error loading command line\n\t-> " + err.Error())
	}

	if d, err := c.LoadFile(k); err != nil {
		if !d {
			return errors.New("config: error loading file\n\t-> " + err.Error())
		}
		log.Printf("config: error loading default file\n\t-> " + err.Error())
	}

	// parse configuration in global configuration var
	if err := k.Unmarshal("", c); err != nil {
		return errors.New("config: error parsing configuration\n\t-> " + err.Error())
	}

	if err := c.Valid(false); err != nil {
		log.Printf("config: configuration is not valid\n\t-> %v", err)
		if err := c.Valid(true); err != nil {
			return errors.New("config: default configuration is not valid either\n\t-> " + err.Error())
		}
	}

	log.Printf("Configuration loaded from file: %s", configuration.ConfigurationFile)

	// print configuration values
	if c.Debug {
		log.Printf("Configuration read:\n\t%v", k)
		log.Printf("Configuration parsed:\n\t%v", c)
	}

	return nil
}
