package hokuto

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
)

var compressedManPageSuffixes = []string{".gz", ".bz2", ".xz", ".zst", ".lz", ".lzma", ".Z"}

func isCompressedManPage(path string) bool {
	for _, suffix := range compressedManPageSuffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func isManSectionDir(name string) bool {
	if !strings.HasPrefix(name, "man") || len(name) <= len("man") {
		return false
	}
	for _, r := range name[len("man"):] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func isEnglishManLocale(name string) bool {
	lower := strings.ToLower(name)
	return lower == "c" || lower == "posix" || lower == "en" || strings.HasPrefix(lower, "en_") || strings.HasPrefix(lower, "en.") || strings.HasPrefix(lower, "en@")
}

func removePackagedPath(path string, execCtx *Executor) error {
	if err := os.RemoveAll(path); err == nil {
		return nil
	}
	return execCtx.Run(exec.Command("rm", "-rf", "--", path))
}

func replacePackagedManSymlink(path, target string, execCtx *Executor) error {
	newPath := path + ".gz"
	newTarget := target
	if !isCompressedManPage(target) {
		newTarget += ".gz"
	}
	if err := os.Remove(path); err == nil {
		if err := os.Symlink(newTarget, newPath); err == nil {
			return nil
		}
	}
	if err := execCtx.Run(exec.Command("rm", "-f", "--", path, newPath)); err != nil {
		return err
	}
	return execCtx.Run(exec.Command("ln", "-s", "--", newTarget, newPath))
}

// normalizePackagedManPages applies the same kind of package-output tidying as
// makepkg: discard non-English localized manuals and reproducibly gzip the
// manuals that remain. It must run before manifest generation so transformed
// paths remain owned by the package.
func normalizePackagedManPages(outputDir string, execCtx *Executor) error {
	manRoot := filepath.Join(outputDir, "usr", "share", "man")
	entries, err := os.ReadDir(manRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read man directory: %w", err)
	}

	var compressionRoots []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(manRoot, entry.Name())
		if isManSectionDir(entry.Name()) {
			compressionRoots = append(compressionRoots, path)
			continue
		}
		if isEnglishManLocale(entry.Name()) {
			if err := filepath.WalkDir(path, func(candidate string, child fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if candidate != path && child.IsDir() && isManSectionDir(child.Name()) {
					compressionRoots = append(compressionRoots, candidate)
					return filepath.SkipDir
				}
				return nil
			}); err != nil {
				return fmt.Errorf("scan English man locale %s: %w", entry.Name(), err)
			}
			continue
		}
		if err := removePackagedPath(path, execCtx); err != nil {
			return fmt.Errorf("remove non-English man directory %s: %w", entry.Name(), err)
		}
	}

	type manSymlink struct {
		path, target, resolved string
	}
	var regularFiles []string
	var symlinks []manSymlink
	for _, root := range compressionRoots {
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || isCompressedManPage(path) {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(path)
				if err != nil {
					return err
				}
				resolved, _ := filepath.EvalSymlinks(path)
				symlinks = append(symlinks, manSymlink{path: path, target: target, resolved: resolved})
				return nil
			}
			if info.Mode().IsRegular() {
				regularFiles = append(regularFiles, path)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("scan retained man pages: %w", err)
		}
	}

	const gzipBatchSize = 128
	for start := 0; start < len(regularFiles); start += gzipBatchSize {
		end := min(start+gzipBatchSize, len(regularFiles))
		args := []string{"-9", "-n", "-f", "--"}
		args = append(args, regularFiles[start:end]...)
		if err := execCtx.Run(exec.Command("gzip", args...)); err != nil {
			return fmt.Errorf("compress man pages: %w", err)
		}
	}

	for _, link := range symlinks {
		if link.resolved == "" {
			continue
		}
		resolvedCompressed := link.resolved
		if !isCompressedManPage(resolvedCompressed) {
			resolvedCompressed += ".gz"
		}
		if _, err := os.Stat(resolvedCompressed); err != nil {
			continue
		}
		if err := replacePackagedManSymlink(link.path, link.target, execCtx); err != nil {
			return fmt.Errorf("compress man-page symlink %s: %w", link.path, err)
		}
	}

	return nil
}
