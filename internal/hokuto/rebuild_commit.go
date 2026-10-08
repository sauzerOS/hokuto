package hokuto

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// revisionBumpLine describes one recipe's revision bump in a commit body,
// in the form the repository's hook uses for version bumps:
// "dav1d: 1.5.4: 2 → 3". bumped is bumpRecipeRevision's "version revision";
// note, when set, follows in parentheses.
func revisionBumpLine(name, bumped, note string) string {
	line := name + ": " + bumped
	if version, rev, ok := strings.Cut(bumped, " "); ok {
		if n, err := strconv.Atoi(rev); err == nil && n > 1 {
			line = fmt.Sprintf("%s: %s: %d → %d", name, version, n-1, n)
		}
	}
	if note != "" {
		line += " (" + note + ")"
	}
	return line
}

// commitRevisionBumps commits the version files of a rebuild's revision bumps
// in root: subject (the rebuild's reason) as the subject, one
// revisionBumpLine per recipe as the body. hokuto init-repos installs a
// prepare-commit-msg hook that puts its own version lines in front of a
// message, which would push the reason out of the subject, so hooks do not
// run for this commit (the repository's others, git-lfs's, have nothing to do
// for version files).
func commitRevisionBumps(root, subject string, lines, paths []string) error {
	msg := subject
	if len(lines) > 0 {
		msg += "\n\n" + strings.Join(lines, "\n")
	}
	// Commit only these paths so unrelated staged changes stay out.
	args := append([]string{"-C", root, "-c", "core.hooksPath=/dev/null", "commit", "-m", msg, "--"}, paths...)
	if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("git commit in %s failed: %v: %s", root, err, strings.TrimSpace(string(out)))
	}
	return nil
}
