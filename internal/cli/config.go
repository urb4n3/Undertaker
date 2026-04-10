package cli

import (
	"fmt"

	"github.com/urb4n3/undertaker/internal/config"
	"github.com/urb4n3/undertaker/internal/tools"
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

	// Discover and display external tool status.
	reg := tools.Discover(cfg)
	fmt.Println("External tools:")
	printToolInfo(reg.FLOSS)
	printToolInfo(reg.Capa)
	printToolInfo(reg.YARA)

	return nil
}

func printToolInfo(ti tools.ToolInfo) {
	if ti.Available {
		fmt.Printf("  %-8s %s (v%s)\n", ti.Name+":", ti.Path, ti.Version)
	} else {
		reason := ti.Error
		if reason == "" {
			reason = "not found"
		}
		fmt.Printf("  %-8s unavailable — %s\n", ti.Name+":", reason)
	}
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	path, err := config.InitConfig()
	if err != nil {
		return err
	}
	fmt.Printf("Created default config at: %s\n", path)
	return nil
}
