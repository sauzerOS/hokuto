package hokuto

// Introspection data for cross-built packages.
//
// gobject-introspection cannot scan a library built for another architecture:
// g-ir-scanner runs the library it scans. Cross builds therefore leave
// introspection out, and a PyGObject application (blueman) on the target found
// no typelib for GTK, Pango or GLib. The native build of the same version has
// them, and x86_64 and aarch64 are both LP64 with the same C type sizes and
// alignment, which is all the typelib's struct and offset data depends on: its
// typelibs, .gir and Vala files describe the aarch64 library just as well. A
// native cross build of a recipe that uses gobject-introspection copies them
// from the published x86_64 package of each of its outputs.

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// introspectionDataSourceArch is the architecture whose packages lend their
// introspection data to cross-built ones.
const introspectionDataSourceArch = "x86_64"

// crossIntrospectionDirs are the package directories that hold introspection
// data: compiled typelibs, their .gir sources, and the Vala bindings
// generated from them.
var crossIntrospectionDirs = []string{
	"usr/lib/girepository-1.0/",
	"usr/share/gir-1.0/",
	"usr/share/vala/vapi/",
}

// recipeUsesIntrospection reports whether a recipe's native build depends on
// gobject-introspection, so its packages are expected to carry typelibs.
func recipeUsesIntrospection(pkgDir string) bool {
	deps, err := parseDependsFile(pkgDir)
	if err != nil {
		return false
	}
	for _, dep := range deps {
		if dep.Cross || dep.CrossNative {
			continue
		}
		if dep.Name == "gobject-introspection" {
			return true
		}
		for _, alt := range dep.Alternatives {
			if alt == "gobject-introspection" {
				return true
			}
		}
	}
	return false
}

// isIntrospectionDataPath reports whether an archive member (no leading slash)
// is a file of crossIntrospectionDirs.
func isIntrospectionDataPath(name string) bool {
	for _, dir := range crossIntrospectionDirs {
		if strings.HasPrefix(name, dir) && len(name) > len(dir) && !strings.Contains(name[len(dir):], "/") {
			return true
		}
	}
	return false
}

// addCrossIntrospectionData copies, into each output of a native cross build
// (the main package in outputDir, split packages under splitRoot), the
// introspection data of the x86_64 package of the same name and version that
// the cross build does not provide itself. A missing x86_64 package leaves the
// output without introspection data, with a warning.
func addCrossIntrospectionData(pkgDir, outputPkgName, outputDir, splitRoot, version, revision string, cfg *Config, logger io.Writer) {
	if cfg.Values["HOKUTO_CROSS_ARCH"] == "" || cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" {
		return
	}
	if !recipeUsesIntrospection(pkgDir) {
		return
	}
	if logger == nil {
		logger = os.Stdout
	}

	outputs := map[string]string{outputPkgName: outputDir}
	if names, err := discoverSplitOutputDirs(splitRoot); err == nil {
		for _, name := range names {
			outputs[name] = filepath.Join(splitRoot, name)
		}
	}

	index, err := getCachedRemoteIndex(cfg, true)
	if err != nil {
		fmt.Fprintf(logger, "%s%s\n", colArrow.Sprint("-> "), colWarn.Sprintf("Warning: no remote index for the x86_64 introspection data of %s: %v", outputPkgName, err))
		return
	}

	for name, dir := range outputs {
		entry := introspectionSourceEntry(index, name, version, revision)
		if entry == nil {
			fmt.Fprintf(logger, "%s%s\n", colArrow.Sprint("-> "), colWarn.Sprintf("Warning: no x86_64 package of %s %s-%s to take its introspection data from", name, version, revision))
			continue
		}
		tarball, cleanup, err := introspectionSourceTarball(*entry)
		if err != nil {
			fmt.Fprintf(logger, "%s%s\n", colArrow.Sprint("-> "), colWarn.Sprintf("Warning: cannot fetch %s for its introspection data: %v", entry.Filename, err))
			continue
		}
		copied, err := copyIntrospectionData(tarball, dir)
		cleanup()
		if err != nil {
			fmt.Fprintf(logger, "%s%s\n", colArrow.Sprint("-> "), colWarn.Sprintf("Warning: copying the introspection data of %s: %v", entry.Filename, err))
			continue
		}
		if copied > 0 {
			fmt.Fprint(logger, colArrow.Sprint("-> "))
			fmt.Fprintf(logger, "%s\n", colNote.Sprintf("Added %d introspection files of %s from %s", copied, name, entry.Filename))
		}
	}
}

// introspectionSourceEntry returns the x86_64 package of name at exactly
// version-revision, the optimized variant first.
func introspectionSourceEntry(index []RepoEntry, name, version, revision string) *RepoEntry {
	var found *RepoEntry
	for i := range index {
		e := &index[i]
		if e.Type == "meta" || e.Name != name || e.Arch != introspectionDataSourceArch || e.Version != version || e.Revision != revision {
			continue
		}
		if found == nil || e.Variant == "optimized" {
			found = e
		}
	}
	return found
}

// introspectionSourceTarball returns a local copy of entry: the one in BinDir,
// or a download verified against the index.
func introspectionSourceTarball(entry RepoEntry) (string, func(), error) {
	local := filepath.Join(BinDir, entry.Filename)
	if _, err := os.Stat(local); err == nil {
		return local, func() {}, nil
	}
	if BinaryMirror == "" {
		return "", nil, fmt.Errorf("no HOKUTO_MIRROR configured")
	}
	dir, cleanup, err := privateTempDir("hokuto-introspection-")
	if err != nil {
		return "", nil, err
	}
	dest := filepath.Join(dir, entry.Filename)
	url := BinaryMirror + "/" + entry.Filename
	if err := downloadFileWithOptions(url, url, dest, downloadOptions{Quiet: true}); err != nil {
		cleanup()
		return "", nil, err
	}
	if entry.B3Sum != "" {
		sum, err := ComputeChecksum(dest, nil)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		if sum != entry.B3Sum {
			cleanup()
			return "", nil, fmt.Errorf("checksum mismatch: expected %s, got %s", entry.B3Sum, sum)
		}
	}
	return dest, cleanup, nil
}

// copyIntrospectionData extracts the introspection data of a package archive
// into outputDir, leaving files the output already has alone, and returns how
// many files it added.
func copyIntrospectionData(tarballPath, outputDir string) (int, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		return 0, err
	}
	defer zr.Close()

	copied := 0
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return copied, err
		}
		name := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		if !isIntrospectionDataPath(name) {
			continue
		}
		dest := filepath.Join(outputDir, filepath.FromSlash(name))
		if _, err := os.Lstat(dest); err == nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return copied, err
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				return copied, err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return copied, err
			}
			if err := out.Close(); err != nil {
				return copied, err
			}
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, dest); err != nil {
				return copied, err
			}
		default:
			continue
		}
		copied++
	}
	return copied, nil
}
