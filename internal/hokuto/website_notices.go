package hokuto

// Notices on the build pages of the website: notices.json, which rounds.html
// and packages.html show above their tables. One notice per ID; hokuto adds,
// replaces and removes them (a held python upgrade, for now).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// WebsiteNotice is one entry of notices.json.
type WebsiteNotice struct {
	ID      string `json:"id"`
	Level   string `json:"level"` // "warn" or "ok"
	Title   string `json:"title"`
	Text    string `json:"text"`
	Updated string `json:"updated"`
}

// setWebsiteNotice adds notice to notices.json, replacing the one with its
// ID, and pushes the website repository.
func setWebsiteNotice(notice WebsiteNotice) {
	notice.Updated = time.Now().UTC().Format(time.RFC3339)
	updateWebsiteNotices(fmt.Sprintf("Notice: %s", notice.Title), func(notices []WebsiteNotice) []WebsiteNotice {
		for i := range notices {
			if notices[i].ID == notice.ID {
				notices[i] = notice
				return notices
			}
		}
		return append(notices, notice)
	})
}

// removeWebsiteNotice removes the notice with id from notices.json.
func removeWebsiteNotice(id string) {
	updateWebsiteNotices("Notice removed: "+id, func(notices []WebsiteNotice) []WebsiteNotice {
		kept := notices[:0]
		for _, n := range notices {
			if n.ID != id {
				kept = append(kept, n)
			}
		}
		return kept
	})
}

// updateWebsiteNotices rewrites notices.json with change and commits and
// pushes it when it changed. Without a website checkout nothing happens.
func updateWebsiteNotices(commitMsg string, change func([]WebsiteNotice) []WebsiteNotice) {
	websiteRepo := WebsiteRepo
	if _, err := os.Stat(filepath.Join(websiteRepo, ".git")); err != nil {
		debugf("No website repository at %s; notice not published\n", websiteRepo)
		return
	}
	defer lockWebsiteRepo(websiteRepo)()

	path := filepath.Join(websiteRepo, "notices.json")
	notices, err := readWebsiteNotices(path)
	if err != nil {
		colWarn.Printf("Warning: %v\n", err)
		return
	}
	before, _ := json.Marshal(notices)
	notices = change(notices)
	if notices == nil {
		notices = []WebsiteNotice{}
	}
	after, _ := json.Marshal(notices)
	if string(before) == string(after) {
		return
	}
	data, err := json.MarshalIndent(notices, "", "  ")
	if err != nil {
		colWarn.Printf("Warning: failed to encode the website notices: %v\n", err)
		return
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		colWarn.Printf("Warning: failed to write %s: %v\n", path, err)
		return
	}
	if err := exec.Command("git", "-C", websiteRepo, "add", "--", "notices.json").Run(); err != nil {
		debugf("Warning: git add notices.json failed: %v\n", err)
	}
	if err := exec.Command("git", "-C", websiteRepo, "commit", "-m", commitMsg, "--", "notices.json").Run(); err != nil {
		debugf("Note: git commit of notices.json skipped or failed: %v\n", err)
	}
	if err := pushWebsiteRepo(websiteRepo); err != nil {
		colWarn.Printf("Warning: failed to push the website notice: %v\n", err)
	}
}

func readWebsiteNotices(path string) ([]WebsiteNotice, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var notices []WebsiteNotice
	if err := json.Unmarshal(data, &notices); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return notices, nil
}
