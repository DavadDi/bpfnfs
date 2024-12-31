package config

import (
	"flag"

	"github.com/spf13/pflag"
)

func SetFlags(pflag *pflag.FlagSet) {
	pflag.AddGoFlagSet(flag.CommandLine)
	pflag.StringVar(&Config.ConfigPath, "config-path", "", "specify config file path")

	pflag.Set("logtostderr", "false")
	pflag.Set("alsologtostderr", "false")
	pflag.Set("log_file", "")
}
