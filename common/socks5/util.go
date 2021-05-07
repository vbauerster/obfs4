package socks5

import (
	"bufio"
	"io"
	"os"
	"strings"
)

func readLines(r io.Reader, limit uint) ([]string, error) {
	lines := make([]string, 0, limit)
	scanner := bufio.NewScanner(r)
	for i := 0; scanner.Scan() && i < int(limit); i++ {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	return lines, scanner.Err()
}

func readAuthFile(p string) (auth string, err error) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	ll, err := readLines(f, 1)
	if err != nil {
		return
	}
	return ll[0], nil
}
