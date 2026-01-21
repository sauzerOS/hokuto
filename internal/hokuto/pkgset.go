package hokuto

import (
	"bufio"
	"os"
	"strings"
)

// Pkgset represents a named collection of package names.
type Pkgset struct {
	Name     string
	Packages []string
}

// loadPkgsets reads the pkgset configuration from PkgsetFile.
// Format:
// setname:
// pkg1
// pkg2
func loadPkgsets() (map[string][]string, error) {
	f, err := os.Open(PkgsetFile)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string][]string), nil
		}
		return nil, err
	}
	defer f.Close()

	sets := make(map[string][]string)
	var currentSetName string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if before, ok := strings.CutSuffix(line, ":"); ok {
			currentSetName = before
			continue
		}

		if currentSetName != "" {
			sets[currentSetName] = append(sets[currentSetName], line)
		}
	}

	return sets, scanner.Err()
}
