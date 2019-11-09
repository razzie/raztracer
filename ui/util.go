package ui

import (
	"fmt"
	"strings"
)

func colorize(text string) string {
	normal := currentTheme.TextColor
	highlight := currentTheme.HighlightTextColor
	return fmt.Sprintf("[%s]%s[%s]", highlight, text, normal)
}

func getAutocompleteFunc(words []string) func(string) []string {
	return func(currentText string) (results []string) {
		if len(currentText) == 0 {
			return
		}

		for _, word := range words {
			if strings.HasPrefix(strings.ToLower(word), strings.ToLower(currentText)) {
				results = append(results, word)
			}
		}

		return
	}
}
