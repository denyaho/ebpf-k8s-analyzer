package config

import (
	"flag"
)

type Config struct {
	DirName string
}

func ConfigParse(arguments []string) *Config {
	config := Config{}
	flagset := CreateParser(arguments, &config)
	flagset.Parse(arguments[1:])
	return &config
}

func CreateParser(arguments []string, config *Config) *flag.FlagSet {
	fs := flag.NewFlagSet("http-server-starter-go", flag.ContinueOnError)

	fs.StringVar(&config.DirName, "directory", "", "Directory to serve files from")
	return fs
}
