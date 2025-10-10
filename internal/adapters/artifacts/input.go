package artifacts

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode"
)

// WriteTempInput serialises the provided lines into a temporary file that can be
// fed as stdin to external tools. It returns the file path together with a
// cleanup function that removes the file when no longer needed.
func WriteTempInput(prefix string, lines []string) (string, func(), error) {
	name := sanitizePrefix(prefix)
	pattern := fmt.Sprintf("passive-rec-%s-*.txt", name)

	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", nil, err
	}

	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := writer.WriteString(line); err != nil {
			writer.Flush()
			file.Close()
			cleanup()
			return "", nil, err
		}
		if err := writer.WriteByte('\n'); err != nil {
			writer.Flush()
			file.Close()
			cleanup()
			return "", nil, err
		}
	}
	if err := writer.Flush(); err != nil {
		file.Close()
		cleanup()
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, err
	}

	return path, cleanup, nil
}

func sanitizePrefix(prefix string) string {
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" {
		return "input"
	}

	var builder strings.Builder
	for _, r := range trimmed {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			builder.WriteRune(unicode.ToLower(r))
		case r == '-' || r == '_':
			builder.WriteRune('-')
		default:
			builder.WriteRune('-')
		}
	}

	result := strings.Trim(builder.String(), "-")
	if result == "" {
		return "input"
	}
	return result
}
