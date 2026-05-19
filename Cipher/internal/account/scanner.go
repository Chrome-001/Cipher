package account

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Platform struct {
	Name     string
	URL      string // %s = username
	NotFound []int  // status codes indicating NOT found (defaults to 404)
}

type Result struct {
	Platform string
	URL      string
	Found    bool
	Status   int
}

// Platforms is the list of supported social/dev platforms to check.
var Platforms = []Platform{
	{Name: "GitHub", URL: "https://github.com/%s"},
	{Name: "GitLab", URL: "https://gitlab.com/%s"},
	{Name: "Bitbucket", URL: "https://bitbucket.org/%s"},
	{Name: "Twitter/X", URL: "https://twitter.com/%s"},
	{Name: "Instagram", URL: "https://www.instagram.com/%s/"},
	{Name: "TikTok", URL: "https://www.tiktok.com/@%s"},
	{Name: "YouTube", URL: "https://www.youtube.com/@%s"},
	{Name: "Twitch", URL: "https://www.twitch.tv/%s"},
	{Name: "Reddit", URL: "https://www.reddit.com/user/%s"},
	{Name: "Pinterest", URL: "https://www.pinterest.com/%s/"},
	{Name: "Snapchat", URL: "https://www.snapchat.com/add/%s"},
	{Name: "LinkedIn", URL: "https://www.linkedin.com/in/%s"},
	{Name: "Medium", URL: "https://medium.com/@%s"},
	{Name: "Dev.to", URL: "https://dev.to/%s"},
	{Name: "Hashnode", URL: "https://hashnode.com/@%s"},
	{Name: "Keybase", URL: "https://keybase.io/%s"},
	{Name: "Steam", URL: "https://steamcommunity.com/id/%s"},
	{Name: "HackerNews", URL: "https://news.ycombinator.com/user?id=%s"},
	{Name: "Pastebin", URL: "https://pastebin.com/u/%s"},
	{Name: "SoundCloud", URL: "https://soundcloud.com/%s"},
	{Name: "Spotify", URL: "https://open.spotify.com/user/%s"},
	{Name: "Behance", URL: "https://www.behance.net/%s"},
	{Name: "Dribbble", URL: "https://dribbble.com/%s"},
	{Name: "Fiverr", URL: "https://www.fiverr.com/%s"},
	{Name: "CodePen", URL: "https://codepen.io/%s"},
	{Name: "HuggingFace", URL: "https://huggingface.co/%s"},
	{Name: "Mastodon", URL: "https://mastodon.social/@%s"},
	{Name: "Bluesky", URL: "https://bsky.app/profile/%s"},
	{Name: "Flickr", URL: "https://www.flickr.com/people/%s"},
	{Name: "Tumblr", URL: "https://%s.tumblr.com"},
	{Name: "ProductHunt", URL: "https://www.producthunt.com/@%s"},
	{Name: "Replit", URL: "https://replit.com/@%s"},
	{Name: "Kaggle", URL: "https://www.kaggle.com/%s"},
	{Name: "npm", URL: "https://www.npmjs.com/~%s"},
	{Name: "PyPI", URL: "https://pypi.org/user/%s/"},
	{Name: "DockerHub", URL: "https://hub.docker.com/u/%s"},
	{Name: "StackOverflow", URL: "https://stackoverflow.com/users/%s"},
	{Name: "Gravatar", URL: "https://en.gravatar.com/%s"},
	{Name: "About.me", URL: "https://about.me/%s"},
	{Name: "Linktree", URL: "https://linktr.ee/%s"},
}

type Scanner struct {
	Username string
	Threads  int
	client   *http.Client
}

func NewScanner(username string, threads int) *Scanner {
	return &Scanner{
		Username: username,
		Threads:  threads,
		client: &http.Client{
			Timeout: 12 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		},
	}
}

// Scan checks the username across all platforms concurrently.
// Results (all, not just found) are sent to the returned channel.
func (s *Scanner) Scan() <-chan Result {
	out := make(chan Result, len(Platforms))
	sem := make(chan struct{}, s.Threads)
	var wg sync.WaitGroup

	for _, p := range Platforms {
		wg.Add(1)
		sem <- struct{}{}

		go func(p Platform) {
			defer wg.Done()
			defer func() { <-sem }()

			url := fmt.Sprintf(p.URL, s.Username)
			result := Result{Platform: p.Name, URL: url}

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				out <- result
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

			resp, err := s.client.Do(req)
			if err != nil {
				out <- result
				return
			}
			resp.Body.Close()

			result.Status = resp.StatusCode
			result.Found = isFound(resp.StatusCode, p.NotFound)
			out <- result
		}(p)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

func isFound(status int, notFoundCodes []int) bool {
	// If the platform has custom not-found codes use those
	if len(notFoundCodes) > 0 {
		for _, c := range notFoundCodes {
			if status == c {
				return false
			}
		}
		return true
	}
	// Default: 200 = found, anything else = not found / unknown
	return status == 200
}
