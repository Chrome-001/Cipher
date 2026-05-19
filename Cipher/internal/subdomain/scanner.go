package subdomain

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Subdomain string
	IPs       []string
	Source    string
}

type Scanner struct {
	Domain  string
	Threads int
	client  *http.Client
}

type crtEntry struct {
	NameValue string `json:"name_value"`
}

func NewScanner(domain string, threads int) *Scanner {
	return &Scanner{
		Domain:  strings.ToLower(strings.TrimSpace(domain)),
		Threads: threads,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		},
	}
}

// FromCRT queries certificate transparency logs via crt.sh
func (s *Scanner) FromCRT() ([]Result, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", s.Domain)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Cipher/1.0)")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	var entries []crtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crt.sh parse error: %w", err)
	}

	seen := make(map[string]bool)
	var results []Result

	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			// strip wildcard prefix
			if strings.HasPrefix(name, "*.") {
				name = name[2:]
			}
			if name == "" || name == s.Domain || seen[name] {
				continue
			}
			if !strings.HasSuffix(name, "."+s.Domain) {
				continue
			}
			seen[name] = true

			ips, _ := net.LookupHost(name)
			results = append(results, Result{
				Subdomain: name,
				IPs:       ips,
				Source:    "crt.sh",
			})
		}
	}

	return results, nil
}

// BruteForce performs DNS brute-force using the provided wordlist.
// Results are sent to the returned channel; the channel is closed when done.
func (s *Scanner) BruteForce(wordlist []string, known map[string]bool) <-chan Result {
	out := make(chan Result, 64)

	go func() {
		defer close(out)
		sem := make(chan struct{}, s.Threads)
		var wg sync.WaitGroup

		for _, word := range wordlist {
			word = strings.TrimSpace(word)
			if word == "" || strings.HasPrefix(word, "#") {
				continue
			}
			sub := fmt.Sprintf("%s.%s", word, s.Domain)
			if known[sub] {
				continue
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(sub string) {
				defer wg.Done()
				defer func() { <-sem }()

				ips, err := net.LookupHost(sub)
				if err == nil && len(ips) > 0 {
					out <- Result{
						Subdomain: sub,
						IPs:       ips,
						Source:    "bruteforce",
					}
				}
			}(sub)
		}

		wg.Wait()
	}()

	return out
}
