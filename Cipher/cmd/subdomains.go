package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"cipher/internal/output"
	"cipher/internal/subdomain"
	"cipher/internal/wordlists"

	"github.com/spf13/cobra"
)

var subdomainsCmd = &cobra.Command{
	Use:     "subdomains -d <domain> [flags]",
	Aliases: []string{"sub", "subs"},
	Short:   "Enumerate subdomains via crt.sh and DNS brute-force",
	Example: `  cipher subdomains -d example.com
  cipher subdomains -d example.com -w mylist.txt -t 50 -o results.txt
  cipher subdomains -d example.com --no-bruteforce`,
	RunE: runSubdomains,
}

var (
	subDomain       string
	subWordlist     string
	subThreads      int
	subOutput       string
	subNoBrute      bool
	subNoCRT        bool
)

func init() {
	subdomainsCmd.Flags().StringVarP(&subDomain, "domain", "d", "", "Target domain (required)")
	subdomainsCmd.Flags().StringVarP(&subWordlist, "wordlist", "w", "", "Custom subdomain wordlist file")
	subdomainsCmd.Flags().IntVarP(&subThreads, "threads", "t", 30, "Concurrent DNS threads")
	subdomainsCmd.Flags().StringVarP(&subOutput, "output", "o", "", "Save results to file")
	subdomainsCmd.Flags().BoolVar(&subNoBrute, "no-bruteforce", false, "Skip DNS brute-force")
	subdomainsCmd.Flags().BoolVar(&subNoCRT, "no-crt", false, "Skip crt.sh lookup")
	_ = subdomainsCmd.MarkFlagRequired("domain")
}

func runSubdomains(cmd *cobra.Command, args []string) error {
	output.Section("Subdomain Enumeration")
	output.Info(fmt.Sprintf("Target: %s%s%s", "\033[1m", subDomain, "\033[0m"))

	scanner := subdomain.NewScanner(subDomain, subThreads)
	known := make(map[string]bool)
	found := 0

	var fw *output.FileWriter
	if subOutput != "" {
		var err error
		fw, err = output.NewFileWriter(subOutput)
		if err != nil {
			return fmt.Errorf("cannot open output file: %w", err)
		}
		defer fw.Close()
		output.Info(fmt.Sprintf("Saving to: %s", subOutput))
	}

	// --- crt.sh ---
	if !subNoCRT {
		output.Info("Querying crt.sh certificate transparency logs...")
		crtResults, err := scanner.FromCRT()
		if err != nil {
			output.Warn(fmt.Sprintf("crt.sh error: %v", err))
		} else {
			for _, r := range crtResults {
				known[r.Subdomain] = true
				ipStr := strings.Join(r.IPs, ", ")
				output.Found(r.Source, r.Subdomain, ipStr)
				if fw != nil {
					fw.Write(fmt.Sprintf("%s\t%s\t%s", r.Source, r.Subdomain, ipStr))
				}
				found++
			}
			output.Info(fmt.Sprintf("crt.sh returned %d unique subdomains", len(crtResults)))
		}
	}

	// --- Brute-force ---
	if !subNoBrute {
		wl := wordlists.Subdomains()
		if subWordlist != "" {
			custom, err := loadWordlistFile(subWordlist)
			if err != nil {
				return fmt.Errorf("cannot read wordlist: %w", err)
			}
			wl = append(wl, custom...)
		}

		output.Info(fmt.Sprintf("DNS brute-force: %d words, %d threads...", len(wl), subThreads))

		ch := scanner.BruteForce(wl, known)
		for r := range ch {
			ipStr := strings.Join(r.IPs, ", ")
			output.Found(r.Source, r.Subdomain, ipStr)
			if fw != nil {
				fw.Write(fmt.Sprintf("%s\t%s\t%s", r.Source, r.Subdomain, ipStr))
			}
			found++
		}
	}

	output.Summary(found, -1, "subdomains")
	return nil
}

func loadWordlistFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}
