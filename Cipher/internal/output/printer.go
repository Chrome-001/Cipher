package output

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	reset  = "\033[0m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	blue   = "\033[34m"
	purple = "\033[35m"
)

var mu sync.Mutex

func Banner() {
	fmt.Printf("%s%s", cyan, bold)
	fmt.Println(`
 ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗
██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗
██║     ██║██████╔╝███████║█████╗  ██████╔╝
██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
╚██████╗██║██║     ██║  ██║███████╗██║  ██║
 ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝`)
	fmt.Printf("%s", reset)
	fmt.Printf("%s  OSINT Recon: Subdomains • Accounts • Directories%s\n\n", dim, reset)
}

func Found(label, value, extra string) {
	mu.Lock()
	defer mu.Unlock()
	if extra != "" {
		fmt.Printf("  %s[+]%s %s%-20s%s %s%s%s  %s%s%s\n",
			green, reset, bold, label, reset, green, value, reset, dim, extra, reset)
	} else {
		fmt.Printf("  %s[+]%s %s%-20s%s %s%s%s\n",
			green, reset, bold, label, reset, green, value, reset)
	}
}

func NotFound(label, value string) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Printf("  %s[-]%s %-20s %s%s%s\n", dim, reset, label, dim, value, reset)
}

func Info(msg string) {
	fmt.Printf("  %s[*]%s %s\n", cyan, reset, msg)
}

func Warn(msg string) {
	fmt.Printf("  %s[!]%s %s%s%s\n", yellow, reset, yellow, msg, reset)
}

func Error(msg string) {
	fmt.Printf("  %s[x]%s %s%s%s\n", red, reset, red, msg, reset)
}

func Section(title string) {
	fmt.Printf("\n%s%s  ══ %s ══%s\n\n", bold, purple, strings.ToUpper(title), reset)
}

func Summary(found, total int, label string) {
	fmt.Printf("\n  %s%s[✓] Found %d/%d %s%s\n\n", bold, green, found, total, label, reset)
}

// FileWriter writes results to a file
type FileWriter struct {
	path string
	file *os.File
	mu   sync.Mutex
}

func NewFileWriter(path string) (*FileWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &FileWriter{path: path, file: f}, nil
}

func (fw *FileWriter) Write(line string) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fmt.Fprintln(fw.file, line)
}

func (fw *FileWriter) Close() {
	fw.file.Close()
}
