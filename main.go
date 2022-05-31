package main

import (
	"os"

	"github.com/knadh/koanf"
	flag "github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var configuration *Config
var log *zap.Logger

// initialize global configuration and logging
func LoadConfigurationAndLogger() error {

	// init loader
	atom := zap.NewAtomicLevel()
	encoderCfg := zap.NewProductionEncoderConfig()
	log = zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderCfg),
		zapcore.Lock(os.Stdout),
		atom,
	))

	log.Info("main: logger initialized")

	// init configuration
	k := koanf.New(".")
	f := flag.NewFlagSet("config", flag.ContinueOnError)
	if configuration == nil {
		configuration = &Config{}
	}

	if err := configuration.Load(k, f); err != nil {
		return err
	}

	// update log level after configuration is loaded
	atomLvl, err := zap.ParseAtomicLevel(configuration.LogLevel)
	if err != nil {
		log.Info("main: update log level", zap.String("level", configuration.LogLevel))
		atom.SetLevel(atomLvl.Level())
	}

	return nil
}

func main() {
	defer log.Sync()
	// Load server
	if err := LoadConfigurationAndLogger(); err != nil {
		log.Fatal("main: error loading configuration", zap.Error(err))
	}
	log.Fatal("main: error loading server", zap.Error(LoadServer()))
}
