package wordlists

import (
	"bufio"
	_ "embed"
	"strings"
)

//go:embed subdomains.txt
var subdomainsRaw string

//go:embed dirs.txt
var dirsRaw string

func Subdomains() []string {
	return parseLines(subdomainsRaw)
}

func Dirs() []string {
	return parseLines(dirsRaw)
}

func parseLines(raw string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
