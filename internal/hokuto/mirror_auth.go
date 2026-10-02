package hokuto

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/term"
)

// A binary mirror can require a login (HTTP basic auth in front of it). The
// login is kept in /etc/hokuto/mirror-auth as "user:password" and sent with
// every request to the mirror. When the mirror answers 401, hokuto asks for
// it on the terminal and, once a download with it succeeds, stores it in the
// target root, so a system bootstrapped by hokutostrap knows it too and it is
// only ever entered once.

const mirrorAuthRelPath = "etc/hokuto/mirror-auth"

// mirrorLoginAttempts bounds the prompts per run, leaving room for a typo.
const mirrorLoginAttempts = 3

var mirrorAuth = struct {
	sync.Mutex
	user, pass string
	loaded     bool
	prompts    int
	unsaved    bool // entered in this run, not yet stored
}{}

// mirrorAuthPath is where the login of the root hokuto installs into lives.
func mirrorAuthPath() string {
	return filepath.Join(rootDir, mirrorAuthRelPath)
}

// mirrorAuthCandidates lists the files a login is read from: the target
// root's, then the host's when installing into another root (hokutostrap
// reuses the login of the system it runs on).
func mirrorAuthCandidates() []string {
	paths := []string{mirrorAuthPath()}
	if host := filepath.Join("/", mirrorAuthRelPath); host != paths[0] {
		paths = append(paths, host)
	}
	return paths
}

func parseMirrorAuth(data string) (user, pass string, ok bool) {
	line, _, _ := strings.Cut(strings.TrimSpace(data), "\n")
	user, pass, ok = strings.Cut(strings.TrimSpace(line), ":")
	if !ok || user == "" {
		return "", "", false
	}
	return user, pass, true
}

func loadMirrorAuthLocked() {
	if mirrorAuth.loaded {
		return
	}
	mirrorAuth.loaded = true
	for _, path := range mirrorAuthCandidates() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if user, pass, ok := parseMirrorAuth(string(data)); ok {
			mirrorAuth.user, mirrorAuth.pass = user, pass
			debugf("Using the mirror login from %s\n", path)
			return
		}
	}
}

// isMirrorURL reports whether rawURL points at the configured binary mirror.
func isMirrorURL(rawURL string) bool {
	if BinaryMirror == "" {
		return false
	}
	mirror, err := url.Parse(BinaryMirror)
	if err != nil {
		return false
	}
	target, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(target.Scheme, mirror.Scheme) && strings.EqualFold(target.Host, mirror.Host)
}

// setMirrorAuthHeader adds the mirror login to a request for the mirror and
// returns the user it sent ("" for none). A URL carrying its own user info
// (HOKUTO_MIRROR=https://user:pass@...) is left to that.
func setMirrorAuthHeader(req *http.Request) string {
	if req.URL.User != nil || !isMirrorURL(req.URL.String()) {
		return ""
	}
	mirrorAuth.Lock()
	defer mirrorAuth.Unlock()
	loadMirrorAuthLocked()
	if mirrorAuth.user == "" {
		return ""
	}
	req.SetBasicAuth(mirrorAuth.user, mirrorAuth.pass)
	return mirrorAuth.user + ":" + mirrorAuth.pass
}

// promptMirrorLogin handles a 401 from the mirror for a request sent with
// login sent. It reports whether to retry: with a login another download
// entered meanwhile, or with one asked for now.
func promptMirrorLogin(sent string) bool {
	mirrorAuth.Lock()
	defer mirrorAuth.Unlock()
	if current := mirrorAuth.user + ":" + mirrorAuth.pass; mirrorAuth.user != "" && current != sent {
		return true
	}
	if mirrorAuth.prompts >= mirrorLoginAttempts || !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}
	mirrorAuth.prompts++

	host := BinaryMirror
	if u, err := url.Parse(BinaryMirror); err == nil {
		host = u.Host
	}
	var user, pass string
	WithPrompt(func() {
		prepareDependencyProgressLogOutput()
		colArrow.Print("-> ")
		if sent == "" {
			colWarn.Printf("The binary mirror %s requires a login.\n", host)
		} else {
			colWarn.Printf("The mirror login was not accepted by %s.\n", host)
		}
		// Shown as typed: it is a download password, and seeing it avoids
		// typos. One reader for both lines, so nothing typed ahead is lost.
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("   User: ")
		line, _ := reader.ReadString('\n')
		user = strings.TrimSpace(line)
		fmt.Print("   Password: ")
		line, _ = reader.ReadString('\n')
		pass = strings.TrimRight(line, "\r\n")
	})
	if user == "" {
		return false
	}
	mirrorAuth.user, mirrorAuth.pass = user, pass
	mirrorAuth.unsaved = true
	return true
}

// mirrorLoginError explains a 401 that could not be resolved.
func mirrorLoginError() error {
	return fmt.Errorf("the binary mirror requires a login: run hokuto in a terminal to enter it, or put user:password in %s", mirrorAuthPath())
}

// saveMirrorAuthIfNew stores a login entered in this run, once a download
// with it has worked, so a mistyped one is never kept.
func saveMirrorAuthIfNew() {
	mirrorAuth.Lock()
	defer mirrorAuth.Unlock()
	if !mirrorAuth.unsaved {
		return
	}
	mirrorAuth.unsaved = false
	path := mirrorAuthPath()
	data := []byte(mirrorAuth.user + ":" + mirrorAuth.pass + "\n")
	// Directly when the target is writable (a root hokuto runs in, a user
	// owned bootstrap directory), as root otherwise.
	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err == nil {
		err = os.WriteFile(path, data, 0o644)
	}
	if err != nil {
		err = writeStateFile(path, data)
	}
	if err != nil {
		colWarn.Printf("Warning: could not save the mirror login to %s: %v\n", path, err)
		return
	}
	colArrow.Print("-> ")
	colSuccess.Printf("Mirror login saved to %s\n", path)
}
