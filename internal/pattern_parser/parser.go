package patternparser

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
)

// ParseTxtPatternsFromFile загружает паттерны из txt-файла
func ParseTxtPatternsFromFile(filePath string) ([]string, error) {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	data := string(bytes)
	lines := strings.Split(data, "\n")
	var patterns []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	return patterns, nil
}

// ParseTxtPatternsFromURL загружает паттерны по URL
func ParseTxtPatternsFromURL(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("bad response: " + resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	data := string(body)
	lines := strings.Split(data, "\n")
	var patterns []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	return patterns, nil
}
