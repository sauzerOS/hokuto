package hokuto

import (
	"bufio"
	"os"
	"strings"
)

// PreferFile (/etc/hokuto/hokuto.prefer) answers the alternative-dependency
// question (xwayland needs xlibre | xorg-server) once for every package: it
// lists package names, one or more per line, # starting a comment. When none
// of a dependency's alternatives is installed, the first listed name among
// them is chosen without asking. An installed alternative still wins, so a
// preference never replaces what the system already has.

// loadPreferredPackages returns the names in PreferFile, in file order.
func loadPreferredPackages() []string {
	f, err := os.Open(PreferFile)
	if err != nil {
		return nil
	}
	defer f.Close()
	var names []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		names = append(names, strings.Fields(line)...)
	}
	return names
}

// preferredAlternative returns the first PreferFile entry among available, or
// "" when the file names none of them.
func preferredAlternative(available []string) string {
	for _, name := range loadPreferredPackages() {
		for _, alt := range available {
			if alt == name {
				return alt
			}
		}
	}
	return ""
}
