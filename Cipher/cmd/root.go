package cmd

import (
	"cipher/internal/output"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cipher",
	Short: "OSINT recon: subdomains, accounts, directories",
	Long: `Cipher — OSINT Reconnaissance Tool
  Enumerate subdomains, find accounts across platforms, and fuzz directories.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		output.Banner()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		output.Error(err.Error())
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(subdomainsCmd)
	rootCmd.AddCommand(accountsCmd)
	rootCmd.AddCommand(dirsCmd)
}
