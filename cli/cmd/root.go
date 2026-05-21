package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tun0access",
	Short: "tun0access — one-command free VPN access across many countries",
	Long: `tun0access is a cross-platform CLI that connects you to free VPN servers
around the world using existing open-source backends (VPN Gate, ProtonVPN free,
and others). Pick a country, hit enter, and you're on tun0.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(doctorCmd)
}
