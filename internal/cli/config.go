package cli

import (
	"fmt"

	"github.com/urb4n3/undertaker/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration and detected tools",
	RunE:  runConfig,
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create default configuration file",
	RunE:  runConfigInit,
}

func init() {
	configCmd.AddCommand(configInitCmd)
}

func runConfig(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	path, _ := config.ConfigPath()
	fmt.Printf("Config file: %s\n\n", path)
	fmt.Println(string(data))

	return nil
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	path, err := config.InitConfig()
	if err != nil {
		return err
	}
	fmt.Printf("Created default config at: %s\n", path)
	return nil
}
