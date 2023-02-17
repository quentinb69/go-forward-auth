package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	flag "github.com/spf13/pflag" // POSIX compliant
	"go.uber.org/zap"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	PrivateKey        string           `koanf:"PrivateKey"`
	Certificate       string           `koanf:"Certificate"`
	Port              uint             `koanf:"Port"`
	CookieDomain      string           `koanf:"CookieDomain"`
	CookieName        string           `koanf:"CookieName"`
	TokenExpire       time.Duration    `koanf:"TokenExpire"`
	TokenRefresh      time.Duration    `koanf:"TokenRefresh"`
	HtmlFile          string           `koanf:"HtmlFile"`
	JwtSecretKey      string           `koanf:"JwtSecretKey"`
	CsrfSecretKey     string           `koanf:"CsrfSecretKey"`
	LogLevel          string           `koanf:"LogLevel"`
	MagicIp           string           `koanf:"MagicIp"`
	Users             map[string]*User `koanf:"Users"`
	ConfigurationFile []string
	StringToHash      string
}

const defaultConfigurationFile = "default.config.yml"
const defaultHtmlFile = "default.index.html"

// validate data, and set default values if init is true
func (c *Config) Valid(init bool) error {

	if c.PrivateKey == "" && c.Certificate == "" && init {
		log.Info("config: generating default key pair for tls")
		c.PrivateKey = "./gfa_server.key"
		c.Certificate = "./gfa_server.crt"
		GenerateKeyPair(2048, c.PrivateKey, c.Certificate)
	}
	if _, err := tls.LoadX509KeyPair(c.Certificate, c.PrivateKey); err != nil {
		return errors.New("config: bad key pair\n\t-> " + err.Error())
	}
	if c.Port < 1 || c.Port > 65534 {
		if !init {
			return errors.New("config: bad Port")
		}
		c.Port = 8000
		log.Info("config: setting default value", zap.Uint("Port", c.Port))
	}
	if c.CookieName == "" {
		if !init {
			return errors.New("config: missing CookieName")
		}
		c.CookieName = "GFA"
		log.Info("config: setting default value", zap.String("CookieName", c.CookieName))
	}
	if c.TokenExpire < 1 {
		if !init {
			return errors.New("config: TokenExpire is too small")
		}
		c.TokenExpire = 90
		log.Info("config: setting default value", zap.Duration("TokenExpire", c.TokenExpire))
	}
	if c.TokenRefresh >= c.TokenExpire {
		if !init {
			return errors.New("config: TokenRefresh must be smaller than TokenExpire")
		}
		c.TokenRefresh = c.TokenExpire / 2
		log.Info("config: setting default value", zap.Duration("TokenRefresh", c.TokenRefresh))
	}
	if c.HtmlFile == "" {
		if !init {
			return errors.New("config: missing HtmlFile")
		}
		c.HtmlFile = defaultHtmlFile
		log.Info("config: setting default value", zap.String("HtmlFile", c.HtmlFile))
	}
	if _, err := os.Stat(c.HtmlFile); err != nil {
		return errors.New("config: html template error\r\t-> " + err.Error())
	}
	if len(c.JwtSecretKey) < 32 {
		if !init {
			return errors.New("config: JwtSecretKey is too small")
		}
		log.Info("config: JwtSecretKey provided is too weak, generating secure one...", zap.Int("length", len(c.JwtSecretKey)))
		array := GenerateRandomBytes(64)
		if len(*array) < 64 {
			return errors.New("config : error generating JwtSecretKey")
		}
		c.JwtSecretKey = string(*array)
	}
	if len(c.CsrfSecretKey) != 32 {
		if !init {
			return errors.New("config: CsrfSecretKey must be 32 character long")
		}
		log.Info("config: CsrfSecretKey provided is too weak, generating secure one...", zap.Int("length", len(c.CsrfSecretKey)))
		array := GenerateRandomBytes(32)
		if len(*array) < 32 {
			return errors.New("config : error generating CsrfSecretKey")
		}
		c.CsrfSecretKey = string(*array)
	}
	if len(c.MagicIp) < 12 {
		if !init {
			return errors.New("config: MagicIp is too small")
		}
		log.Info("config: MagicIp provided is too weak, generating secure one...", zap.Int("length", len(c.MagicIp)))
		array := GenerateRandomBytes(12)
		if len(*array) < 12 {
			return errors.New("config : error generating MagicIp")
		}
		// magic ip need to be passed to jwt
		c.MagicIp = base64.StdEncoding.EncodeToString(*array)
	}
	if _, err := zap.ParseAtomicLevel(c.LogLevel); err != nil || c.LogLevel == "" {
		if !init {
			return errors.New("config: bad LogLevel")
		}
		c.LogLevel = "info"
		log.Info("config: setting default value", zap.String("LogLevel", c.LogLevel))
	}

	return nil
}

// load configuration from command line
func (c *Config) LoadCommandeLine(f *flag.FlagSet) {

	f.Usage = func() {
		fmt.Print(f.FlagUsages())
		os.Exit(0)
	}

	if !f.HasFlags() {
		f.StringSlice("config", c.ConfigurationFile, "Link to one or more configurations files.")
		f.String("log", c.LogLevel, "Select log level.")
		f.String("hash", c.StringToHash, "Password to hash (if hash is set, program will exit after showing answer).")
	}

	f.Parse(os.Args[1:])

	c.LogLevel, _ = f.GetString("log")
	c.ConfigurationFile, _ = f.GetStringSlice("config")
	c.StringToHash, _ = f.GetString("hash")
}

// load configuration from file
func (c *Config) LoadFile(k *koanf.Koanf) (isDefault bool, err error) {
	if k == nil {
		return false, errors.New("config: no koanf provided")
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

	c.LoadCommandeLine(f)
	if c.StringToHash != "" {
		log.Debug("config: hashing string", zap.String("value", c.StringToHash))
		log.Info("config: hashed string", zap.String("value", GetHash(c.StringToHash)))
		return errors.New("config: not an error")
	}

	if d, err := c.LoadFile(k); err != nil {
		if !d {
			return errors.New("config: error loading file\n\t-> " + err.Error())
		}
		log.Info("config: error loading default file", zap.Error(err))
	}

	// parse configuration in global configuration var
	if err := k.Unmarshal("", c); err != nil {
		return errors.New("config: error parsing configuration\n\t-> " + err.Error())
	}

	if err := c.Valid(false); err != nil {
		log.Info("config: configuration is not valid", zap.Error(err))
		if err := c.Valid(true); err != nil {
			return errors.New("config: default configuration is not valid either\n\t-> " + err.Error())
		}
	}

	log.Info("Configuration loaded", zap.Strings("files", c.ConfigurationFile))

	return nil
}
