package hokuto

import (
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// The update --build-missing-binaries list says why each recipe needs a new
// binary, taken from the commit that last changed its version file. bump's
// ABI rebuilds write "rebuild for libplist (libplist-2.0.so.4, ...) ABI
// change", and a manual bump may say "rebuild for llvm 22.1.8".

// versionCommitMessage returns the full message of the last commit that
// changed pkgName's version file, or "" when there is none (not in git).
func versionCommitMessage(pkgName string) string {
	pkgDir, err := findPackageMetadataDir(pkgName)
	if err != nil || pkgDir == "" {
		return ""
	}
	out, err := exec.Command("git", "-C", pkgDir, "log", "-1", "--format=%B", "--", "version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// parenthesizedList matches the soname lists ABI rebuild commits carry.
var parenthesizedList = regexp.MustCompile(`\s*\([^)]*\)`)

// rebuildReason extracts the "rebuild for ..." part of a commit message,
// without the parenthesized library lists: "rebuild for libplist ABI change".
// It returns "" when the message gives no rebuild reason.
func rebuildReason(message string) string {
	for _, line := range strings.Split(message, "\n") {
		idx := strings.Index(strings.ToLower(line), "rebuild for ")
		if idx < 0 {
			continue
		}
		reason := parenthesizedList.ReplaceAllString(line[idx:], "")
		reason = strings.Join(strings.Fields(reason), " ")
		return strings.TrimRight(reason, ".,;: ")
	}
	return ""
}

// versionCommitMessages looks up versionCommitMessage for every package. Each
// lookup is a git process, so they run a few at a time.
func versionCommitMessages(pkgNames []string) map[string]string {
	messages := make(map[string]string, len(pkgNames))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, pkgName := range pkgNames {
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			message := versionCommitMessage(name)
			mu.Lock()
			messages[name] = message
			mu.Unlock()
		}(pkgName)
	}
	wg.Wait()
	return messages
}
