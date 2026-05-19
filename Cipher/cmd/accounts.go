package cmd

import (
	"fmt"
	"sort"

	"cipher/internal/account"
	"cipher/internal/output"

	"github.com/spf13/cobra"
)

var accountsCmd = &cobra.Command{
	Use:     "accounts -u <username> [flags]",
	Aliases: []string{"user", "username", "osint"},
	Short:   "Find accounts across 40+ platforms by username",
	Example: `  cipher accounts -u johndoe
  cipher accounts -u johndoe -t 20 -o found.txt
  cipher accounts -u johndoe --show-all`,
	RunE: runAccounts,
}

var (
	accUsername string
	accThreads  int
	accOutput   string
	accShowAll  bool
)

func init() {
	accountsCmd.Flags().StringVarP(&accUsername, "username", "u", "", "Username to search (required)")
	accountsCmd.Flags().IntVarP(&accThreads, "threads", "t", 15, "Concurrent HTTP threads")
	accountsCmd.Flags().StringVarP(&accOutput, "output", "o", "", "Save found accounts to file")
	accountsCmd.Flags().BoolVar(&accShowAll, "show-all", false, "Show not-found results too")
	_ = accountsCmd.MarkFlagRequired("username")
}

func runAccounts(cmd *cobra.Command, args []string) error {
	output.Section("Account Enumeration")
	output.Info(fmt.Sprintf("Username:  %s%s%s", "\033[1m", accUsername, "\033[0m"))
	output.Info(fmt.Sprintf("Platforms: %d", len(account.Platforms)))

	scanner := account.NewScanner(accUsername, accThreads)

	var fw *output.FileWriter
	if accOutput != "" {
		var err error
		fw, err = output.NewFileWriter(accOutput)
		if err != nil {
			return fmt.Errorf("cannot open output file: %w", err)
		}
		defer fw.Close()
		output.Info(fmt.Sprintf("Saving to:  %s", accOutput))
	}

	fmt.Println()

	// Collect all results first so we can sort by platform name
	var results []account.Result
	for r := range scanner.Scan() {
		results = append(results, r)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Platform < results[j].Platform
	})

	found := 0
	for _, r := range results {
		if r.Found {
			output.Found(r.Platform, r.URL, fmt.Sprintf("HTTP %d", r.Status))
			if fw != nil {
				fw.Write(fmt.Sprintf("[FOUND] %s\t%s", r.Platform, r.URL))
			}
			found++
		} else if accShowAll {
			statusStr := ""
			if r.Status != 0 {
				statusStr = fmt.Sprintf("HTTP %d", r.Status)
			}
			output.NotFound(r.Platform, fmt.Sprintf("%s  %s", r.URL, statusStr))
		}
	}

	output.Summary(found, len(account.Platforms), "accounts found")
	return nil
}
