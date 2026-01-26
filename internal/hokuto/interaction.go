package hokuto

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ParseSelectionIndices parses a comma-separated list of numbers or negative numbers (for exclusion).
// It returns a slice of 0-based indices and a boolean indicating if it's an exclusion list.
func ParseSelectionIndices(input string, max int) ([]int, bool, error) {
	if input == "" {
		return nil, false, nil
	}

	parts := strings.Split(input, ",")
	indices := make(map[int]bool)
	exclude := false

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		isNeg := strings.HasPrefix(part, "-")
		idxStr := part
		if isNeg {
			exclude = true
			idxStr = strings.TrimPrefix(part, "-")
		}

		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			return nil, false, fmt.Errorf("invalid number: %s", part)
		}

		if idx <= 0 || idx > max {
			return nil, false, fmt.Errorf("number out of range (1-%d): %d", max, idx)
		}

		indices[idx-1] = true
	}

	var result []int
	if exclude {
		for i := 0; i < max; i++ {
			if !indices[i] {
				result = append(result, i)
			}
		}
	} else {
		for idx := range indices {
			result = append(result, idx)
		}
		sort.Ints(result)
	}

	return result, exclude, nil
}

// AskForSelection prompts the user to select items from a list by number.
// It supports 'a' for all, 'y' for all (default), 'n' for none/cancel,
// and comma-separated numbers or -numbers.
func AskForSelection(prompt string, count int) ([]int, bool) {
	interactiveMu.Lock()
	defer interactiveMu.Unlock()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		colArrow.Print("-> ")
		colNote.Print(prompt + " ")

		if !scanner.Scan() {
			return nil, false
		}

		input := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(input)

		// Defaults/All
		if lower == "" || lower == "y" || lower == "yes" || lower == "a" || lower == "all" {
			indices := make([]int, count)
			for i := 0; i < count; i++ {
				indices[i] = i
			}
			return indices, true
		}

		// Cancel
		if lower == "n" || lower == "no" || lower == "c" || lower == "cancel" {
			return nil, false
		}

		// Selection
		indices, _, err := ParseSelectionIndices(input, count)
		if err != nil {
			colError.Printf("Error: %v\n", err)
			continue
		}

		if len(indices) == 0 {
			colWarn.Println("No items selected.")
			continue
		}

		return indices, true
	}
}
