package hokuto

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// preparePackageBuildLog returns an installed build log when available. For an
// uninstalled package it resolves a cached or remote binary, expands it in a
// temporary directory, and returns the packaged log without installing files.
func preparePackageBuildLog(pkgName string, cfg *Config) (string, func(), error) {
	installedLog := filepath.Join(rootDir, "var", "db", "hokuto", "installed", pkgName, "log.xz")
	if _, err := os.Stat(installedLog); err == nil {
		return installedLog, func() {}, nil
	}

	archivePath := ""
	if strings.Contains(pkgName, "@") {
		archivePath, _, _, _ = findCachedRequestedBinaryTarball(pkgName, cfg)
	} else {
		archivePath = findCachedBinaryTarball(pkgName, cfg)
	}

	tmpDir, err := os.MkdirTemp("", "hokuto-log-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("create temporary log directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }

	if archivePath == "" {
		index, indexErr := GetCachedRemoteIndex(cfg)
		if indexErr != nil {
			cleanup()
			return "", func() {}, fmt.Errorf("package %s is not installed and the remote index is unavailable: %w", pkgName, indexErr)
		}
		entry, entryErr := GetRemotePackageEntry(pkgName, cfg, index)
		if entryErr != nil {
			cleanup()
			return "", func() {}, entryErr
		}
		if BinaryMirror == "" {
			cleanup()
			return "", func() {}, fmt.Errorf("package %s is not installed and no binary mirror is configured", pkgName)
		}

		filename := entry.Filename
		if filename == "" {
			filename = StandardizeRemoteName(entry.Name, entry.Version, entry.Revision, entry.Arch, entry.Variant)
		}
		archivePath = filepath.Join(tmpDir, filepath.Base(filename))
		url := strings.TrimRight(BinaryMirror, "/") + "/" + filename
		if err := downloadFileWithOptions(url, url, archivePath, downloadOptions{}); err != nil {
			cleanup()
			return "", func() {}, fmt.Errorf("download %s: %w", filename, err)
		}
		if entry.B3Sum != "" {
			sum, sumErr := ComputeChecksum(archivePath, nil)
			if sumErr != nil {
				cleanup()
				return "", func() {}, fmt.Errorf("verify %s: %w", filename, sumErr)
			}
			if sum != entry.B3Sum {
				cleanup()
				return "", func() {}, fmt.Errorf("checksum mismatch for %s: expected %s, got %s", filename, entry.B3Sum, sum)
			}
			colArrow.Print("-> ")
			colSuccess.Printf("Checksum verified: %s\n", entry.B3Sum)
		}
	}

	logPath := filepath.Join(tmpDir, "log.xz")
	colArrow.Print("-> ")
	colSuccess.Printf("Unpacking build log for %s\n", pkgName)
	if err := extractPackagedBuildLog(archivePath, logPath); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("extract package archive: %w", err)
	}
	return logPath, cleanup, nil
}

// extractPackagedBuildLog expands only the saved log from a package archive.
// Avoiding a full extraction keeps large packages cheap to inspect and prevents
// archive symlinks or unrelated payload files from affecting the host.
func extractPackagedBuildLog(archivePath, destination string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		return err
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("build log not present in archive")
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		if hdr.Typeflag != tar.TypeReg || !strings.HasPrefix(name, "var/db/hokuto/installed/") || !strings.HasSuffix(name, "/log.xz") {
			continue
		}
		out, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, tr)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
}

func displayCompressedBuildLog(logPath string) error {
	f, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	defer f.Close()

	xr, err := xz.NewReader(f)
	if err != nil {
		return fmt.Errorf("decompress log: %w", err)
	}
	data, err := io.ReadAll(xr)
	if err != nil {
		return fmt.Errorf("read log: %w", err)
	}
	data = sanitizeTerminalLog(data)

	pagerFields := strings.Fields(os.Getenv("PAGER"))
	if len(pagerFields) == 0 {
		pagerFields = []string{"less", "-R"}
	} else if filepath.Base(pagerFields[0]) == "less" {
		hasColorOption := false
		for _, arg := range pagerFields[1:] {
			if arg == "-r" || arg == "-R" || arg == "--raw-control-chars" || arg == "--RAW-CONTROL-CHARS" ||
				(strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && (strings.Contains(arg[1:], "R") || strings.Contains(arg[1:], "r"))) {
				hasColorOption = true
				break
			}
		}
		if !hasColorOption {
			pagerFields = append(pagerFields, "-R")
		}
	}
	cmd := exec.Command(pagerFields[0], pagerFields[1:]...)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err == nil {
		return nil
	}

	_, err = os.Stdout.Write(data)
	return err
}

// sanitizeTerminalLog keeps printable text and SGR color/style escapes while
// removing cursor movement, line erasure, OSC sequences, and other controls
// recorded by script(1). CRLF becomes LF and a standalone carriage return is
// rendered as a new line instead of overwriting previously displayed output.
func sanitizeTerminalLog(input []byte) []byte {
	output := make([]byte, 0, len(input))
	for i := 0; i < len(input); {
		b := input[i]
		if b == '\x1b' {
			if i+1 >= len(input) {
				break
			}
			switch input[i+1] {
			case '[': // Control Sequence Introducer.
				end := i + 2
				for end < len(input) && (input[end] < 0x40 || input[end] > 0x7e) {
					end++
				}
				if end < len(input) {
					if input[end] == 'm' { // Preserve only Select Graphic Rendition.
						output = append(output, input[i:end+1]...)
					}
					i = end + 1
					continue
				}
				i = len(input)
				continue
			case ']': // Operating System Command; terminated by BEL or ST.
				i += 2
				for i < len(input) {
					if input[i] == '\a' {
						i++
						break
					}
					if input[i] == '\x1b' && i+1 < len(input) && input[i+1] == '\\' {
						i += 2
						break
					}
					i++
				}
				continue
			default:
				i += 2
				continue
			}
		}
		if b == '\r' {
			if i+1 < len(input) && input[i+1] == '\n' {
				i++ // The following iteration emits the LF.
			} else {
				output = append(output, '\n')
				i++
			}
			continue
		}
		if b == '\n' || b == '\t' || b >= 0x20 {
			output = append(output, b)
		}
		i++
	}
	return output
}
