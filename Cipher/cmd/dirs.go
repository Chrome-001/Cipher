package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"cipher/internal/dirfuzz"
	"cipher/internal/output"
	"cipher/internal/wordlists"

	"github.com/spf13/cobra"
)

var dirsCmd = &cobra.Command{
	Use:     "dirs -u <url> [flags]",
	Aliases: []string{"dir", "fuzz", "dirb"},
	Short:   "Brute-force directories and files on a web server",
	Example: `  cipher dirs -u https://example.com
  cipher dirs -u https://example.com -w mylist.txt -t 50
  cipher dirs -u https://example.com -s 200,301,302 -o results.txt`,
	RunE: runDirs,
}

var (
	dirURL      string
	dirWordlist string
	dirThreads  int
	dirOutput   string
	dirStatus   string
)

func init() {
	dirsCmd.Flags().StringVarP(&dirURL, "url", "u", "", "Target URL (required)")
	dirsCmd.Flags().StringVarP(&dirWordlist, "wordlist", "w", "", "Custom directory wordlist file")
	dirsCmd.Flags().IntVarP(&dirThreads, "threads", "t", 20, "Concurrent HTTP threads")
	dirsCmd.Flags().StringVarP(&dirOutput, "output", "o", "", "Save results to file")
	dirsCmd.Flags().StringVarP(&dirStatus, "status", "s", "", "Filter by status codes, comma-separated (e.g. 200,301)")
	_ = dirsCmd.MarkFlagRequired("url")
}

func runDirs(cmd *cobra.Command, args []string) error {
	output.Section("Directory Fuzzing")
	output.Info(fmt.Sprintf("Target:  %s%s%s", "\033[1m", dirURL, "\033[0m"))

	statusFilter, err := parseStatusFilter(dirStatus)
	if err != nil {
		return fmt.Errorf("invalid status filter: %w", err)
	}
	if len(statusFilter) > 0 {
		output.Info(fmt.Sprintf("Filter:  %s", dirStatus))
	}

	wl := wordlists.Dirs()
	if dirWordlist != "" {
		custom, err := loadWordlistFile(dirWordlist)
		if err != nil {
			return fmt.Errorf("cannot read wordlist: %w", err)
		}
		wl = append(wl, custom...)
	}

	output.Info(fmt.Sprintf("Words:   %d | Threads: %d", len(wl), dirThreads))

	var fw *output.FileWriter
	if dirOutput != "" {
		fw, err = output.NewFileWriter(dirOutput)
		if err != nil {
			return fmt.Errorf("cannot open output file: %w", err)
		}
		defer fw.Close()
		output.Info(fmt.Sprintf("Saving:  %s", dirOutput))
	}

	fmt.Println()

	scanner := dirfuzz.NewScanner(dirURL, dirThreads, statusFilter)
	found := 0

	for r := range scanner.Fuzz(wl) {
		colorCode := dirfuzz.StatusColor(r.Status)
		reset := "\033[0m"
		statusStr := fmt.Sprintf("%s%d%s", colorCode, r.Status, reset)
		sizeStr := ""
		if r.Size > 0 {
			sizeStr = fmt.Sprintf("%d bytes", r.Size)
		}
		output.Found(statusStr, r.URL, sizeStr)
		if fw != nil {
			fw.Write(fmt.Sprintf("[%d] %s\t%d bytes", r.Status, r.URL, r.Size))
		}
		found++
	}

	output.Summary(found, -1, "paths discovered")
	return nil
}

func parseStatusFilter(s string) ([]int, error) {
	if s == "" {
		return nil, nil
	}
	var codes []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		code, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid status code", part)
		}
		codes = append(codes, code)
	}
	return codes, nil
}
