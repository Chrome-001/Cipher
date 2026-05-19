package dirfuzz

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL    string
	Status int
	Size   int64
}

type Scanner struct {
	BaseURL    string
	Threads    int
	StatusFilter []int // only report these status codes (empty = all except 404/400)
	client     *http.Client
}

func NewScanner(baseURL string, threads int, statusFilter []int) *Scanner {
	baseURL = strings.TrimRight(baseURL, "/")
	return &Scanner{
		BaseURL:      baseURL,
		Threads:      threads,
		StatusFilter: statusFilter,
		client: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects — capture 301/302
			},
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		},
	}
}

// Fuzz sends HTTP requests for each path in wordlist concurrently.
// Results are sent to the returned channel; channel closed when done.
func (s *Scanner) Fuzz(wordlist []string) <-chan Result {
	out := make(chan Result, 128)
	sem := make(chan struct{}, s.Threads)
	var wg sync.WaitGroup

	go func() {
		defer close(out)

		for _, word := range wordlist {
			word = strings.TrimSpace(word)
			if word == "" || strings.HasPrefix(word, "#") {
				continue
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(path string) {
				defer wg.Done()
				defer func() { <-sem }()

				url := fmt.Sprintf("%s/%s", s.BaseURL, path)

				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Cipher/1.0)")

				resp, err := s.client.Do(req)
				if err != nil {
					return
				}
				resp.Body.Close()

				if s.shouldReport(resp.StatusCode) {
					out <- Result{
						URL:    url,
						Status: resp.StatusCode,
						Size:   resp.ContentLength,
					}
				}
			}(word)
		}

		wg.Wait()
	}()

	return out
}

func (s *Scanner) shouldReport(status int) bool {
	if len(s.StatusFilter) > 0 {
		for _, code := range s.StatusFilter {
			if status == code {
				return true
			}
		}
		return false
	}
	// default: skip 404 and 400
	return status != 404 && status != 400
}

// StatusColor returns an ANSI color string for a status code
func StatusColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "\033[32m" // green
	case code >= 300 && code < 400:
		return "\033[33m" // yellow
	case code >= 400 && code < 500:
		return "\033[31m" // red
	case code >= 500:
		return "\033[35m" // purple
	default:
		return "\033[0m"
	}
}
