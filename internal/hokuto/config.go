package hokuto

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config struct
type Config struct {
	Values       map[string]string
	DefaultStrip bool
	DefaultLTO   bool
}

// Load /etc/hokuto.conf and apply defaults
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
		debugf("=> Using Binary Mirror: %s\n", BinaryMirror)
	}

	SourcesDir = CacheDir + "/sources"
	BinDir = CacheDir + "/bin"
	CacheStore = SourcesDir + "/_cache"
	Installed = rootDir + "/var/db/hokuto/installed"
	WorldFile = filepath.Join(rootDir, "/var/db/hokuto/world")
	WorldMakeFile = filepath.Join(rootDir, "/var/db/hokuto/world_make")
	newPackageDir = "/repo/sauzeros/extra" // default for 'hokuto new'
}
