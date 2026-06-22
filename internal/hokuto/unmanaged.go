package hokuto

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

func normalizeTrackedPath(root, path string) (string, bool) {
	path = strings.TrimSpace(path)
	if path == "" || strings.HasSuffix(path, "/") {
		return "", false
	}

	clean := filepath.ToSlash(filepath.Clean(canonicalizePath(root, path)))
	if clean == "/etc" || clean == "/usr" || strings.HasPrefix(clean, "/etc/") || strings.HasPrefix(clean, "/usr/") {
		return clean, true
	}
	return "", false
}

func loadOwnedSystemFiles(root string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(Installed)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]struct{}{}, nil
		}
		return nil, fmt.Errorf("failed to read installed package db: %w", err)
	}

	owned := make(map[string]struct{})
	var ownedMu sync.Mutex

	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	if len(entries) > 0 && workers > len(entries) {
		workers = len(entries)
	}

	jobs := make(chan os.DirEntry, workers)
	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make(map[string]struct{})
			for entry := range jobs {
				if !entry.IsDir() {
					continue
				}
				manifestPath := filepath.Join(Installed, entry.Name(), "manifest")
				if err := collectOwnedManifestPaths(root, manifestPath, local); err != nil {
					errOnce.Do(func() { firstErr = err })
				}
			}

			ownedMu.Lock()
			for path := range local {
				owned[path] = struct{}{}
			}
			ownedMu.Unlock()
		}()
	}

	for _, entry := range entries {
		jobs <- entry
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return owned, nil
}

func collectOwnedManifestPaths(root, manifestPath string, owned map[string]struct{}) error {
	file, err := os.Open(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to open manifest %s: %w", manifestPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		path := parseManifestFilePath(scanner.Text())
		if normalized, ok := normalizeTrackedPath(root, path); ok {
			owned[normalized] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to scan manifest %s: %w", manifestPath, err)
	}
	return nil
}

func scanUnmanagedSystemFiles(root string, owned map[string]struct{}) ([]string, error) {
	var unmanaged []string
	for _, scanRoot := range []string{"etc", "usr"} {
		absRoot := filepath.Join(root, scanRoot)
		if _, err := os.Lstat(absRoot); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to access %s: %w", absRoot, err)
		}

		err := filepath.WalkDir(absRoot, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				debugf("Skipping unmanaged scan path %s: %v\n", path, err)
				if entry != nil && entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}

			rel, err := filepath.Rel(root, path)
			if err != nil {
				return nil
			}
			trackedPath := "/" + filepath.ToSlash(rel)
			canonicalPath := filepath.ToSlash(filepath.Clean(canonicalizePath(root, trackedPath)))
			if _, ok := owned[canonicalPath]; !ok {
				unmanaged = append(unmanaged, trackedPath)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to scan %s: %w", absRoot, err)
		}
	}

	sort.Strings(unmanaged)
	return unmanaged, nil
}

func handleUnmanagedCommand(cfg *Config) error {
	root := "/"
	if cfg != nil && cfg.Values["HOKUTO_ROOT"] != "" {
		root = cfg.Values["HOKUTO_ROOT"]
	} else if rootDir != "" {
		root = rootDir
	}

	colArrow.Print("-> ")
	colSuccess.Println("Loading installed package manifests")
	owned, err := loadOwnedSystemFiles(root)
	if err != nil {
		return err
	}

	colArrow.Print("-> ")
	colSuccess.Println("Scanning unmanaged files in /etc and /usr")
	unmanaged, err := scanUnmanagedSystemFiles(root, owned)
	if err != nil {
		return err
	}

	if len(unmanaged) == 0 {
		colSuccess.Println("No unmanaged files found in /etc or /usr.")
		return nil
	}

	colWarn.Printf("Found %d unmanaged file(s) in /etc and /usr.\n", len(unmanaged))
	return RunPager("Unmanaged Files", unmanaged)
}
