package hokuto

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func handleInitReposCommand(cfg *Config) error {
	rootDir := cfg.Values["HOKUTO_ROOT"]
	if rootDir == "" {
		rootDir = "/"
	}
	repoDir := filepath.Join(rootDir, "repo")

	repos := []string{"sauzeros", "kde", "cosmic"}
	urls := map[string]string{
		"sauzeros": "https://github.com/sauzerOS/sauzeros",
		"kde":      "https://github.com/sauzerOS/kde",
		"cosmic":   "https://github.com/sauzerOS/cosmic",
	}

	// 1. Check for existing directories
	for _, repo := range repos {
		path := filepath.Join(repoDir, repo)
		if _, err := os.Stat(path); err == nil {
			// Check if it's an actual git repo
			checkCmd := exec.Command("git", "-C", path, "rev-parse", "--is-inside-work-tree")
			if err := checkCmd.Run(); err == nil {
				colArrow.Print("-> ")
				colWarn.Printf("Warning: %s already exists and is a git repository.\n", path)
				return fmt.Errorf("repository %s already exists. Please remove it manually if you want to re-initialize", path)
			}

			// If it exists but is not a git repo, remove it
			colArrow.Print("-> ")
			colWarn.Printf("Removing non-git directory: %s\n", path)
			if os.Geteuid() == 0 {
				if err := os.RemoveAll(path); err != nil {
					return fmt.Errorf("failed to remove existing directory %s natively: %v", path, err)
				}
			} else {
				if err := os.RemoveAll(path); err != nil {
					// Fallback to RootExec (rm -rf) if Go's os.RemoveAll fails (likely permission issue)
					rmCmd := exec.Command("rm", "-rf", path)
					if err := RootExec.Run(rmCmd); err != nil {
						return fmt.Errorf("failed to remove existing directory %s: %v", path, err)
					}
				}
			}
		}
	}

	// 3. Optional repos
	colArrow.Print("-> ")
	enableKDE := askForConfirmation(colSuccess, "Enable KDE repository?")
	colArrow.Print("-> ")
	enableCosmic := askForConfirmation(colSuccess, "Enable Cosmic repository?")

	// 4. Create repo directory if it doesn't exist
	if _, err := os.Stat(repoDir); os.IsNotExist(err) {
		colArrow.Print("-> ")
		colInfo.Printf("Creating repository directory: %s\n", repoDir)
		if os.Geteuid() == 0 {
			if err := os.MkdirAll(repoDir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s natively: %v", repoDir, err)
			}
		} else {
			if err := os.MkdirAll(repoDir, 0o755); err != nil {
				mkdirCmd := exec.Command("mkdir", "-p", repoDir)
				if err := RootExec.Run(mkdirCmd); err != nil {
					return fmt.Errorf("failed to create directory %s: %v", repoDir, err)
				}
			}
		}
	}

	// Ensure the repo directory is owned by the current user
	uid := os.Getuid()
	gid := os.Getgid()
	if os.Geteuid() == 0 {
		if err := os.Chown(repoDir, uid, gid); err != nil {
			colArrow.Print("-> ")
			colWarn.Printf("Warning: failed to set ownership of %s natively: %v\n", repoDir, err)
		}
	} else {
		chownCmd := exec.Command("chown", "-R", fmt.Sprintf("%d:%d", uid, gid), repoDir)
		if err := RootExec.Run(chownCmd); err != nil {
			colArrow.Print("-> ")
			colWarn.Printf("Warning: failed to set ownership of %s: %v\n", repoDir, err)
		}
	}

	// 5. Clone the repositories
	enabledRepos := []string{"sauzeros"}
	if enableKDE {
		enabledRepos = append(enabledRepos, "kde")
	}
	if enableCosmic {
		enabledRepos = append(enabledRepos, "cosmic")
	}

	for _, repo := range enabledRepos {
		targetPath := filepath.Join(repoDir, repo)
		url := urls[repo]

		colArrow.Print("-> ")
		colSuccess.Printf("Cloning %s repository from %s\n", repo, url)

		cloneCmd := exec.Command("git", "clone", url, targetPath)
		cloneCmd.Stdout = os.Stdout
		cloneCmd.Stderr = os.Stderr
		if err := UserExec.Run(cloneCmd); err != nil {
			return fmt.Errorf("failed to clone %s: %v", repo, err)
		}

		// --- git-lfs check AFTER sauzeros clone ---
		if repo == "sauzeros" {
			// Update cfg.Values["HOKUTO_PATH"] temporarily to include the new repo
			// so that if we need to install git-lfs, hokuto knows where to find it.
			oldPath := cfg.Values["HOKUTO_PATH"]
			if oldPath == "" {
				cfg.Values["HOKUTO_PATH"] = targetPath
			} else if !strings.Contains(oldPath, targetPath) {
				cfg.Values["HOKUTO_PATH"] = oldPath + ":" + targetPath
			}
			// Refresh repo paths in the global variable too
			repoPaths = cfg.Values["HOKUTO_PATH"]

			if _, err := exec.LookPath("git-lfs"); err != nil {
				colArrow.Print("-> ")
				colWarn.Println(" git-lfs is required but not installed.")
				colArrow.Print("-> ")
				if askForConfirmation(colInfo, " Would you like to attempt to install git-lfs now?") {
					// Try to install git-lfs via hokuto
					installCmd := exec.Command("hokuto", "install", "git-lfs")
					if err := UserExec.Run(installCmd); err != nil {
						colArrow.Print("-> ")
						colWarn.Printf("Warning: Failed to install git-lfs: %v\n", err)
						colInfo.Println("Please install git-lfs manually for full repository support.")
					}
				}
			} else {
				// Initialize git-lfs for the current user
				exec.Command("git", "lfs", "install").Run()
			}
		}

		// Ensure git-lfs files are pulled
		if _, err := exec.LookPath("git-lfs"); err == nil {
			colArrow.Print("-> ")
			colSuccess.Printf("Downloading LFS assets for %s\n", repo)
			lfsPullCmd := exec.Command("git", "-C", targetPath, "lfs", "pull")
			lfsPullCmd.Stdout = os.Stdout
			lfsPullCmd.Stderr = os.Stderr
			_ = UserExec.Run(lfsPullCmd)
		}

		// Install git hooks
		if err := installGitHooks(targetPath); err != nil {
			colArrow.Print("-> ")
			colWarn.Printf("Warning: failed to install git hooks for %s: %v\n", repo, err)
		}
	}

	colArrow.Print("-> ")
	colSuccess.Println("Repositories initialized successfully.")

	// 6. Update config file
	if err := updateHokutoConfig(rootDir, enableKDE, enableCosmic); err != nil {
		colArrow.Print("-> ")
		colWarn.Printf("Warning: failed to update config file: %v\n", err)
	} else {
		colArrow.Print("-> ")
		colSuccess.Println("Configuration file updated.")
	}

	return nil
}

const gitHookScript = `#!/bin/sh
# Auto-generate commit message lines for any package version bump

case "$2" in
  merge|commit) exit 0 ;;
esac

packages=$(git diff --cached --name-only | grep '/version$')

msg=""
for pkg in $packages; do
  name=$(basename "$(dirname "$pkg")")

  diff_out=$(git diff --cached -U0 "$pkg")

  # Extract old/new upstream versions (field 1 only)
  old=$(echo "$diff_out" \
    | grep '^-' | grep -v '^---' \
    | cut -c2- | awk '{print $1}')

  new=$(echo "$diff_out" \
    | grep '^+' | grep -v '^+++' \
    | cut -c2- | awk '{print $1}')

  if [ -n "$old" ] && [ -n "$new" ] && [ "$old" != "$new" ]; then
    msg="${msg}${name}: ${old} → ${new}\n"
  fi
done

if [ -n "$msg" ]; then
  existing_content=$(cat "$1")
  printf "%b\n%s" "$msg" "$existing_content" > "$1"
fi
`

func installGitHooks(repoPath string) error {
	hooksDir := filepath.Join(repoPath, ".git", "hooks")
	if _, err := os.Stat(hooksDir); os.IsNotExist(err) {
		if err := os.MkdirAll(hooksDir, 0755); err != nil {
			return fmt.Errorf("failed to create hooks directory: %w", err)
		}
	}

	// 1. Write the script file
	scriptPath := filepath.Join(hooksDir, "git-hook-prepare-commit-msg")
	if err := os.WriteFile(scriptPath, []byte(gitHookScript), 0755); err != nil {
		return fmt.Errorf("failed to write hook script: %w", err)
	}

	// 2. Symlink prepare-commit-msg -> git-hook-prepare-commit-msg
	linkPath := filepath.Join(hooksDir, "prepare-commit-msg")
	// Remove if exists to be safe
	_ = os.Remove(linkPath)
	if err := os.Symlink("git-hook-prepare-commit-msg", linkPath); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}

	// 3. Ensure ownership if running as root
	// 3. Ensure ownership if running as root
	if os.Geteuid() == 0 {
		// Use the ownership of the repo directory to match
		info, err := os.Stat(repoPath)
		if err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok {
				uid := int(stat.Uid)
				gid := int(stat.Gid)
				_ = os.Chown(scriptPath, uid, gid)
				_ = os.Chown(linkPath, uid, gid) // lchown usually
				// Note: os.Chown on symlink might behave differently on Linux (usually changes target).
				// We should use os.Lchown for link.
				_ = os.Lchown(linkPath, uid, gid)
			}
		}
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Installed git hooks in %s\n", hooksDir)
	return nil
}

func updateHokutoConfig(rootDir string, enableKDE, enableCosmic bool) error {
	configPath := filepath.Join(rootDir, "etc", "hokuto", "hokuto.conf")

	// Base paths
	basePath := "/repo/sauzeros/core:/repo/sauzeros/extra"
	if enableKDE {
		basePath += ":/repo/kde"
	}
	if enableCosmic {
		basePath += ":/repo/cosmic"
	}

	newLine := fmt.Sprintf("HOKUTO_PATH=%s", basePath)

	var lines []string
	found := false

	// Try reading existing config
	data, err := os.ReadFile(configPath)
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(strings.TrimSpace(line), "HOKUTO_PATH=") {
				lines = append(lines, newLine)
				found = true
			} else {
				lines = append(lines, line)
			}
		}
	}

	if !found {
		lines = append(lines, newLine)
	}

	newContent := strings.Join(lines, "\n")
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}

	// Write back using RootExec to ensure we have permissions
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("hokuto.conf.tmp.%d", os.Getpid()))
	if err := os.WriteFile(tmpFile, []byte(newContent), 0o644); err != nil {
		return fmt.Errorf("failed to create temporary config file: %v", err)
	}

	// Ensure etc dir exists
	etcDir := filepath.Join(rootDir, "etc")
	if _, err := os.Stat(etcDir); os.IsNotExist(err) {
		mkdirCmd := exec.Command("mkdir", "-p", etcDir)
		if err := RootExec.Run(mkdirCmd); err != nil {
			os.Remove(tmpFile)
			return fmt.Errorf("failed to create etc directory: %v", err)
		}
	}

	if os.Geteuid() == 0 {
		if err := os.Rename(tmpFile, configPath); err != nil {
			os.Remove(tmpFile)
			return fmt.Errorf("failed to update config file natively: %v", err)
		}
	} else {
		mvCmd := exec.Command("mv", tmpFile, configPath)
		if err := RootExec.Run(mvCmd); err != nil {
			os.Remove(tmpFile)
			return fmt.Errorf("failed to update config file: %v", err)
		}
	}

	return nil
}
