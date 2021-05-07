package socks5

import (
	"bufio"
	"io"
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
