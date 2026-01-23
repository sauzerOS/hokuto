package hokuto

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Config struct
type Config struct {
	Values       map[string]string
	DefaultStrip bool
	DefaultLTO   bool
}

// Load /etc/hokuto/hokuto.conf and apply defaults
func loadConfig(path string) (*Config, error) {
	cfg := &Config{Values: make(map[string]string)}

	// Attempt to read the file
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`)
			cfg.Values[key] = val
		}
		if err := scanner.Err(); err != nil {
			return cfg, err
		}
	}

	// Merge HOKUTO_* env overrides
	mergeEnvOverrides(cfg)

	// Ensure TMPDIR has a default
	if tmp := cfg.Values["TMPDIR"]; tmp == "" {
		cfg.Values["TMPDIR"] = "/tmp"
	}

	return cfg, nil
}

// Merge HOKUTO_* env overrides
func mergeEnvOverrides(cfg *Config) {
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "HOKUTO_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				cfg.Values[parts[0]] = parts[1]
			}
		}
	}

	// Also import LFS from the environment if present, without overwriting an explicit config file value
	if lfs := os.Getenv("LFS"); lfs != "" {
		// Use key "LFS" in cfg.Values to match environment variable name
		if _, exists := cfg.Values["LFS"]; !exists {
			cfg.Values["LFS"] = lfs
		}
	}
}

func initConfig(cfg *Config) {
	rootDir = cfg.Values["HOKUTO_ROOT"]
	if rootDir == "" {
		rootDir = "/"
	}

	CacheDir = cfg.Values["HOKUTO_CACHE_DIR"]
	if CacheDir == "" {
		CacheDir = "/var/cache/hokuto"
	}

	repoPaths = cfg.Values["HOKUTO_PATH"]
	if repoPaths == "" {
		log.Printf("Warning: HOKUTO_PATH is not set")
	}

	WantDebug = cfg.Values["HOKUTO_DEBUG"]
	if WantDebug == "" {
		WantDebug = "0"
	}
	Debug = false
	if WantDebug == "1" {
		Debug = true
	}

	tmpDir = cfg.Values["TMPDIR"]
	if tmpDir == "" {
		tmpDir = "/tmp"
	}

	HokutoTmpDir = cfg.Values["TMPDIR"]
	if HokutoTmpDir == "" {
		HokutoTmpDir = "/tmp"
	}

	cfg.DefaultStrip = true
	WantStrip := cfg.Values["HOKUTO_STRIP"]
	if WantStrip == "0" {
		cfg.DefaultStrip = false
	}

	cfg.DefaultLTO = false
	WantLTO := cfg.Values["HOKUTO_LTO"]
	if WantLTO == "1" {
		cfg.DefaultLTO = true
	}

	VerifySignature = true
	if cfg.Values["HOKUTO_VERIFY_SIGNATURE"] == "0" {
		VerifySignature = false
	}

	HokutoGeneric = false
	if cfg.Values["HOKUTO_GENERIC"] == "1" {
		HokutoGeneric = true
	}

	activeKeyID = cfg.Values["HOKUTO_KEY_ID"]
	if activeKeyID == "" {
		activeKeyID = officialKeyID
	}

	// Multilib is only supported on x86_64 architecture
	// Automatically disable for aarch64 and other architectures
	EnableMultilib = false
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "386" {
		// Only enable multilib if explicitly requested and on x86_64/386
		if cfg.Values["HOKUTO_MULTILIB"] == "1" {
			EnableMultilib = true
		}
	} else if cfg.Values["HOKUTO_MULTILIB"] == "1" {
		// Warn if multilib is requested on unsupported architecture
		log.Printf("Warning: Multilib is not supported on %s architecture, disabling", runtime.GOARCH)
	}

	// Load the GNU mirror URL if it's set in the config
	if mirror, exists := cfg.Values["GNU_MIRROR"]; exists && mirror != "" {
		gnuMirrorURL = strings.TrimRight(mirror, "/") // Remove trailing slash if present
		debugf("=> Using GNU mirror from config: %s\n", gnuMirrorURL)
	}

	// Set a default mirror if none was provided by the user
	if gnuMirrorURL == "" {
		// mirrors.kernel.org is a reliable and globally distributed mirror, making it an excellent default.
		gnuMirrorURL = "https://mirrors.kernel.org/gnu"
		debugf("=> No GNU mirror configured, using default: %s\n", gnuMirrorURL)
	}

	if mirror, exists := cfg.Values["HOKUTO_MIRROR"]; exists && mirror != "" {
		BinaryMirror = strings.TrimRight(mirror, "/")
		debugf("=> Using Binary Mirror from config: %s\n", BinaryMirror)
	} else if defaultBinaryMirror != "" {
		BinaryMirror = strings.TrimRight(defaultBinaryMirror, "/")
		debugf("=> Using hardcoded default Binary Mirror: %s\n", BinaryMirror)
	}

	SourcesDir = CacheDir + "/sources"
	BinDir = CacheDir + "/bin"
	CacheStore = SourcesDir + "/_cache"
	Installed = rootDir + "/var/db/hokuto/installed"
	WorldFile = filepath.Join(rootDir, "/var/db/hokuto/world")
	WorldMakeFile = filepath.Join(rootDir, "/var/db/hokuto/world_make")
	LockFile = filepath.Join(rootDir, "/etc/hokuto/hokuto.lock")
	newPackageDir = "/repo/sauzeros/extra" // default for 'hokuto new'
}

// saveConfig writes the current configuration map to /etc/hokuto/hokuto.conf
func saveConfig(path string, cfg *Config) error {
	// 1. Prepare data
	var data strings.Builder
	keys := make([]string, 0, len(cfg.Values))
	for k := range cfg.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		data.WriteString(fmt.Sprintf("%s=%s\n", k, cfg.Values[k]))
	}
	content := []byte(data.String())

	// 2. Write if root or destination is writable
	if os.Geteuid() == 0 {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		return os.WriteFile(path, content, 0644)
	}

	// 3. Fallback: Write to temp file and move with RootExec
	tmp, err := os.CreateTemp("", "hokuto-conf-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	// Ensure destination directory exists
	mkdirCmd := exec.Command("mkdir", "-p", filepath.Dir(path))
	if err := RootExec.Run(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Move temp file to path
	mvCmd := exec.Command("mv", tmpPath, path)
	if err := RootExec.Run(mvCmd); err != nil {
		return fmt.Errorf("failed to save config file: %w", err)
	}

	// Set permissions
	chmodCmd := exec.Command("chmod", "644", path)
	_ = RootExec.Run(chmodCmd)

	return nil
}

// setConfigValue updates a value in the config map and saves it to disk
func setConfigValue(cfg *Config, key, value string) error {
	cfg.Values[key] = value

	configPath := ConfigFile
	if root := os.Getenv("HOKUTO_ROOT"); root != "" {
		configPath = filepath.Join(root, "etc", "hokuto", "hokuto.conf")
	}

	if err := saveConfig(configPath, cfg); err != nil {
		return err
	}

	// Re-initialize globals
	initConfig(cfg)
	return nil
}
