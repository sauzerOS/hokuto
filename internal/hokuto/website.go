package hokuto

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// PackageStatus is one recipe's entry in the website's packages.json: its
// last build on each architecture the site tracks (see websiteBuildArch).
type PackageStatus struct {
	PkgName string                   `json:"pkgname"`
	Builds  map[string]*WebsiteBuild `json:"builds,omitempty"`

	// Entries written before builds were kept per architecture. They are
	// read as the x86_64 build and never written again.
	Version string   `json:"version,omitempty"`
	Status  string   `json:"status,omitempty"`
	Log     string   `json:"log,omitempty"`
	Logs    []string `json:"logs,omitempty"`
	Built   string   `json:"built,omitempty"`
}

// WebsiteBuild is the last build of a package on one architecture.
type WebsiteBuild struct {
	Version string `json:"version"`
	Status  string `json:"status"`
	// Built is when this status was recorded (RFC 3339, UTC); packages.html
	// lists the most recent first.
	Built string `json:"built,omitempty"`
	// BuildTime is how long the build ran, in seconds.
	BuildTime int64  `json:"buildtime,omitempty"`
	Log       string `json:"log,omitempty"`
	// Logs lists the kept logs, newest first; Log is Logs[0].
	Logs []string `json:"logs,omitempty"`
	// Outputs are the packages of the last successful build: the recipe's
	// own and its split packages. A failed build keeps them.
	Outputs []WebsiteOutput `json:"outputs,omitempty"`
}

// WebsiteOutput describes one built package.
type WebsiteOutput struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Size is the compressed package, Installed what it takes once installed.
	Size      int64  `json:"size,omitempty"`
	Installed int64  `json:"installed,omitempty"`
	Files     int    `json:"files,omitempty"`
	Manifest  string `json:"manifest,omitempty"`
}

// WebsiteBuildResult is what a build publishes to the website.
type WebsiteBuildResult struct {
	PkgName   string // the recipe
	Arch      string // from websiteBuildArch
	Version   string // version-revision
	Status    string // "success" or "failed"
	LogPath   string
	BuildTime time.Duration
	Outputs   []WebsiteOutputSource
}

// WebsiteOutputSource is a package a successful build created: its staged
// output, which holds its manifest, and its archive in BinDir.
type WebsiteOutputSource struct {
	Name      string
	OutputDir string
	Tarball   string
}

// websiteBuildArch returns the architecture a build of outputPkgName for
// targetArch is listed under on the website, or "" when it is not listed:
// sysroot packages (aarch64-foo) of cross,system builds belong to the build
// host's tooling, not to either system, and a generic x86_64 build only
// repeats the optimized one.
func websiteBuildArch(outputPkgName, targetArch string, cfg *Config) string {
	if archPrefixOf(outputPkgName) != "" {
		return ""
	}
	switch targetArch {
	case "x86_64":
		if cfg != nil && cfg.Values["HOKUTO_GENERIC"] == "1" {
			return ""
		}
		return "x86_64"
	case "aarch64":
		return "aarch64"
	}
	return ""
}

// websiteLogName names a build log on the site. x86_64 logs keep the names
// they always had; other architectures add theirs, so a package's native and
// arm64 builds of one version do not overwrite each other.
func websiteLogName(pkgName, version, arch string) string {
	if arch == "" || arch == "x86_64" {
		return fmt.Sprintf("%s-%s.txt.gz", pkgName, version)
	}
	return fmt.Sprintf("%s-%s-%s.txt.gz", pkgName, version, arch)
}

// websiteLogsKept is how many build logs per package stay on the site. Older
// ones are deleted from the checkout (git history keeps them); GitHub Pages
// sites are limited to 1 GB.
const websiteLogsKept = 3

// writeWebsiteLog stores a build log gzip-compressed; log.html decompresses
// it in the browser. hokuto's own logs are xz files and are recompressed.
func writeWebsiteLog(src, dst string) (err error) {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(dst)
		}
	}()
	gz, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return err
	}
	if strings.HasSuffix(src, ".xz") {
		cmd := exec.Command("xz", "-dc", src)
		cmd.Stdout = gz
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("xz -dc %s: %w", src, err)
		}
	} else {
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		_, err = io.Copy(gz, in)
		in.Close()
		if err != nil {
			return err
		}
	}
	return gz.Close()
}

// recordWebsiteLog makes logRelPath the newest log of entry and returns the
// logs that fall out of the kept window.
func recordWebsiteLog(entry *WebsiteBuild, logRelPath string) []string {
	history := entry.Logs
	if len(history) == 0 && entry.Log != "" {
		history = []string{entry.Log} // entries from before the history existed
	}
	kept := []string{logRelPath}
	for _, old := range history {
		if old != logRelPath {
			kept = append(kept, old)
		}
	}
	var dropped []string
	if len(kept) > websiteLogsKept {
		dropped = kept[websiteLogsKept:]
		kept = kept[:websiteLogsKept]
	}
	entry.Logs = kept
	entry.Log = logRelPath
	return dropped
}

// defaultWebsiteRepo is the sauzerOS.github.io checkout used when
// HOKUTO_WEBSITE_REPO is not set in hokuto.conf.
const defaultWebsiteRepo = "/home/dbz/Documents/sauzerOS.github.io"

// WebsiteRepo is the website checkout build status and logs are pushed to.
var WebsiteRepo = defaultWebsiteRepo

// websiteBuildOf returns entry's build for arch, creating it; a legacy entry
// becomes its x86_64 build first.
func websiteBuildOf(entry *PackageStatus, arch string) *WebsiteBuild {
	if entry.Builds == nil {
		entry.Builds = make(map[string]*WebsiteBuild)
	}
	if entry.Version != "" && entry.Builds["x86_64"] == nil {
		entry.Builds["x86_64"] = &WebsiteBuild{Version: entry.Version, Status: entry.Status, Built: entry.Built, Log: entry.Log, Logs: entry.Logs}
	}
	entry.Version, entry.Status, entry.Log, entry.Logs, entry.Built = "", "", "", nil, ""
	if entry.Builds[arch] == nil {
		entry.Builds[arch] = &WebsiteBuild{}
	}
	return entry.Builds[arch]
}

// UpdateWebsiteStatus records a build in packages.json, stores its log and
// the manifests of the packages it made, and pushes the website repository.
func UpdateWebsiteStatus(r WebsiteBuildResult) error {
	if r.Arch == "" {
		return nil
	}
	websiteRepo := WebsiteRepo
	// Without the checkout (e.g. a build container that does not mount it)
	// there is nothing to update; creating directories there would only
	// leave a stray tree behind.
	if _, err := os.Stat(filepath.Join(websiteRepo, ".git")); err != nil {
		colWarn.Printf("Warning: website repository %s not found; build status for %s not published\n", websiteRepo, r.PkgName)
		return nil
	}
	jsonPath := filepath.Join(websiteRepo, "packages.json")
	logsDir := filepath.Join(websiteRepo, "logs")

	// Ensure logs directory exists
	os.MkdirAll(logsDir, 0755)

	// 1. Read existing JSON
	var packages []PackageStatus
	data, err := os.ReadFile(jsonPath)
	if err == nil {
		if err := json.Unmarshal(data, &packages); err != nil {
			debugf("Warning: failed to unmarshal packages.json: %v\n", err)
			packages = []PackageStatus{}
		}
	} else {
		packages = []PackageStatus{}
	}

	// 2. Store the log, gzip-compressed
	var logRelPath string
	if r.LogPath != "" {
		if _, err := os.Stat(r.LogPath); err == nil {
			logFileName := websiteLogName(r.PkgName, r.Version, r.Arch)
			if err := writeWebsiteLog(r.LogPath, filepath.Join(logsDir, logFileName)); err != nil {
				colWarn.Printf("Warning: failed to store build log for %s: %v\n", r.PkgName, err)
			} else {
				logRelPath = "logs/" + logFileName
			}
		}
	}

	// 3. Update or add package, keeping its last websiteLogsKept logs
	index := -1
	for i, p := range packages {
		if p.PkgName == r.PkgName {
			index = i
			break
		}
	}
	if index < 0 {
		packages = append(packages, PackageStatus{PkgName: r.PkgName})
		index = len(packages) - 1
	}
	build := websiteBuildOf(&packages[index], r.Arch)
	build.Version = r.Version
	build.Status = r.Status
	build.Built = time.Now().UTC().Format(time.RFC3339)
	build.BuildTime = int64(r.BuildTime.Round(time.Second) / time.Second)
	if logRelPath != "" {
		for _, old := range recordWebsiteLog(build, logRelPath) {
			if err := os.Remove(filepath.Join(websiteRepo, old)); err != nil && !errors.Is(err, os.ErrNotExist) {
				debugf("Warning: failed to remove old log %s: %v\n", old, err)
			}
		}
	}
	if r.Status == "success" && len(r.Outputs) > 0 {
		build.Outputs = nil
		for _, src := range r.Outputs {
			out, err := describeWebsiteOutput(websiteRepo, r.Arch, r.Version, src)
			if err != nil {
				colWarn.Printf("Warning: failed to describe %s for the website: %v\n", src.Name, err)
			}
			build.Outputs = append(build.Outputs, out)
		}
	}

	// 4. Save JSON
	newData, err := json.MarshalIndent(packages, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}
	if err := os.WriteFile(jsonPath, newData, 0644); err != nil {
		return fmt.Errorf("failed to write packages.json: %v", err)
	}

	// 5. Commit and push
	// We use git -C to run it in the website repo
	// -A also stages the logs removed above.
	// git add fails on a pathspec that matches nothing, e.g. manifests/
	// before the first successful build.
	addArgs := []string{"-C", websiteRepo, "add", "-A", "--"}
	for _, path := range []string{"packages.json", "logs", "manifests"} {
		if _, err := os.Stat(filepath.Join(websiteRepo, path)); err == nil {
			addArgs = append(addArgs, path)
		}
	}
	addCmd := exec.Command("git", addArgs...)
	if err := addCmd.Run(); err != nil {
		debugf("Warning: git add failed in website repo: %v\n", err)
	}

	commitMsg := fmt.Sprintf("Update status for %s %s (%s)", r.PkgName, r.Version, r.Status)
	if r.Arch != "x86_64" {
		commitMsg = fmt.Sprintf("Update status for %s %s %s (%s)", r.PkgName, r.Version, r.Arch, r.Status)
	}
	commitCmd := exec.Command("git", "-C", websiteRepo, "commit", "-m", commitMsg)
	if err := commitCmd.Run(); err != nil {
		// Commit might fail if there are no changes, which is fine
		debugf("Note: git commit skipped or failed: %v\n", err)
	}

	return pushWebsiteRepo(websiteRepo)
}

// pushWebsiteRepo pushes the website checkout's new commits. The site's
// package-index workflow commits repo.json on its own, so it rebases onto it
// before pushing, and retries if one lands in between.
func pushWebsiteRepo(websiteRepo string) error {
	var pushErr error
	for attempt := 1; attempt <= 3; attempt++ {
		pullCmd := exec.Command("git", "-C", websiteRepo, "pull", "--rebase", "--autostash", "--quiet")
		if out, err := pullCmd.CombinedOutput(); err != nil {
			debugf("Warning: git pull --rebase failed in website repo: %v: %s\n", err, strings.TrimSpace(string(out)))
		}
		out, err := exec.Command("git", "-C", websiteRepo, "push", "--quiet").CombinedOutput()
		if err == nil {
			return nil
		}
		pushErr = fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return fmt.Errorf("failed to push to website repo: %v", pushErr)
}

// describeWebsiteOutput measures a built package and stores its file list as
// manifests/<arch>/<name>.txt.gz, replacing the previous build's. It returns
// what it could find out even when part of it failed.
func describeWebsiteOutput(websiteRepo, arch, version string, src WebsiteOutputSource) (WebsiteOutput, error) {
	out := WebsiteOutput{Name: src.Name, Version: version}
	if info, err := os.Stat(src.Tarball); err == nil {
		out.Size = info.Size()
	}
	// The archive records the installed size. Walking the output instead
	// fails on an asroot build, whose output holds directories only root
	// may enter (cups: etc/cups/ssl).
	if scan, err := scanTarballFull(src.Tarball); err == nil && scan.installedSize > 0 {
		out.Installed = scan.installedSize
	} else {
		installed, err := installedSize(src.OutputDir)
		if err != nil {
			return out, err
		}
		out.Installed = installed
	}

	data, err := readFileAsRoot(filepath.Join(src.OutputDir, "var", "db", "hokuto", "installed", src.Name, "manifest"))
	if err != nil {
		return out, err
	}
	var files []string
	for _, line := range strings.Split(string(data), "\n") {
		entry, ok, err := parseManifestLine(line)
		if err != nil || !ok || strings.HasSuffix(entry.Path, "/") {
			continue
		}
		files = append(files, entry.Path)
	}
	out.Files = len(files)
	rel := filepath.ToSlash(filepath.Join("manifests", arch, src.Name+".txt.gz"))
	dst := filepath.Join(websiteRepo, rel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return out, err
	}
	if err := writeGzipFile(dst, []byte(strings.Join(files, "\n")+"\n")); err != nil {
		return out, err
	}
	out.Manifest = rel
	return out, nil
}

// installedSize adds up the regular files under dir, counting hard linked
// files once, as they take space once installed.
func installedSize(dir string) (int64, error) {
	var total int64
	seen := make(map[[2]uint64]bool)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
			key := [2]uint64{uint64(st.Dev), st.Ino}
			if seen[key] {
				return nil
			}
			seen[key] = true
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func writeGzipFile(dst string, data []byte) (err error) {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := gz.Write(data); err != nil {
		return err
	}
	return gz.Close()
}
