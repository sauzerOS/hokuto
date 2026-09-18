package hokuto

// Deciding whether a recipe has been prepared for cross builds.
//
// Building a package that was never adapted for cross compilation does not
// usually fail: configure scripts fall back to host defaults, the build picks
// up the host's headers and libraries, and the result is a package that looks
// fine until something links against it or it is installed on the target. The
// check below refuses that build instead.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// crossSupportOption marks a recipe as prepared for cross builds, and
// noCrossSupportOption marks one that must never be cross built. Either wins
// over what the recipe looks like.
const (
	crossSupportOption   = "cross"
	noCrossSupportOption = "nocross"
)

// allowUnconfiguredCrossEnv lets a build proceed anyway, for working on a
// recipe that is not adapted yet.
const allowUnconfiguredCrossEnv = "HOKUTO_ALLOW_UNCONFIGURED_CROSS"

// crossAwareBuildMarkers are what an adapted build script uses to tell a cross
// build from a native one. CROSS_PREFIX and HOKUTO_CROSS are what hokuto
// exports; CROSS_COMPILE is the kernel's own spelling, used by linux-rpi4.
var crossAwareBuildMarkers = []string{"CROSS_PREFIX", "HOKUTO_CROSS", "CROSS_COMPILE"}

// packageSupportsCrossBuild reports whether pkgDir's recipe is prepared for a
// cross build, along with a short reason suitable for an error message.
//
// The options file is authoritative when it says anything. Otherwise the recipe
// is inspected: a build script that branches on the cross environment, or a
// depends file carrying cross entries, is taken as adapted. Both are needed --
// low level packages such as brotli and gmp handle CROSS_PREFIX but have too
// few dependencies to have any marked cross, while shadow and linux-rpi4 carry
// cross dependencies without mentioning hokuto's variables in their script.
func packageSupportsCrossBuild(pkgDir string, options map[string]bool) (bool, string) {
	if options[noCrossSupportOption] {
		return false, "its options file says " + noCrossSupportOption
	}
	if options[crossSupportOption] {
		return true, "its options file says " + crossSupportOption
	}

	if marker, ok := buildScriptIsCrossAware(filepath.Join(pkgDir, "build")); ok {
		return true, "its build script uses " + marker
	}

	if deps, err := parseDependsFile(pkgDir); err == nil {
		for _, dep := range deps {
			if dep.Cross || dep.CrossNative {
				return true, "its depends file declares cross dependencies"
			}
		}
	}

	return false, "its build script does not branch on the cross environment and it declares no cross dependencies"
}

// buildScriptIsCrossAware reports whether a build script mentions any of the
// variables that distinguish a cross build, ignoring comments so that a recipe
// is not credited for merely talking about cross compilation.
//
// One idiom is deliberately not counted:
//
//	if [ "${HOKUTO_CROSS:-0}" != "1" ] && [ "$MULTILIB" = "1" ]; then
//
// That is a multilib guard. It only says "skip the 32-bit split when cross
// building", which is about the *host* build being irrelevant to a cross one,
// and says nothing about whether the main build was ever adapted. Crediting it
// let packages such as libva through the gate and straight into a broken build.
func buildScriptIsCrossAware(buildPath string) (string, bool) {
	data, err := os.ReadFile(buildPath)
	if err != nil {
		return "", false
	}

	for _, line := range strings.Split(string(data), "\n") {
		code := stripShellComment(line)
		for _, marker := range crossAwareBuildMarkers {
			if !strings.Contains(code, marker) {
				continue
			}
			if marker == "HOKUTO_CROSS" && isMultilibGuard(code) {
				continue
			}
			return marker, true
		}
	}
	return "", false
}

// isMultilibGuard reports whether a line tests HOKUTO_CROSS only to decide
// whether to build the 32-bit split package.
func isMultilibGuard(code string) bool {
	return strings.Contains(code, "MULTILIB")
}

// stripShellComment removes a trailing comment from a line of shell, leaving
// a '#' that is part of a word (a URL fragment, say) alone.
func stripShellComment(line string) string {
	inSingle, inDouble := false, false
	for i, ch := range line {
		switch {
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '"' && !inSingle:
			inDouble = !inDouble
		case ch == '#' && !inSingle && !inDouble:
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return line[:i]
			}
		}
	}
	return line
}

// unconfiguredCrossBuildAllowed reports whether the operator has asked for
// unadapted recipes to be built anyway.
func unconfiguredCrossBuildAllowed() bool {
	return os.Getenv(allowUnconfiguredCrossEnv) == "1"
}

// crossBuildActive records whether the build currently running is a cross
// build. generateDepends needs it to honour the "nocross" dependency flag, and
// it runs far from where the cross mode is decided.
var crossBuildActive bool

// setCrossBuildActive is called once the build mode for this run is known.
func setCrossBuildActive(v bool) { crossBuildActive = v }

// crossBuildInProgress reports whether a cross build is running.
func crossBuildInProgress() bool { return crossBuildActive }

// Keeping a cross,system package inside its sysroot.
//
// A cross,system package is installed on the build host, so every path it
// stages is a path on the host. A recipe that hardcodes --prefix=/usr instead
// of honouring CROSS_PREFIX therefore packages its aarch64 libraries as
// /usr/lib/..., and installing it replaces the host's native libraries of the
// same name. Nothing fails at build time and the damage only shows up later,
// when the dynamic loader rejects the foreign ELF.

// crossSystemSysrootFor returns the sysroot a cross,system build must stay
// inside, or "" when this build is not one. It reads the same CROSS_PREFIX the
// build script was handed, so the check and the recipe cannot disagree.
func crossSystemSysrootFor(cfg *Config, defaults map[string]string) string {
	if cfg == nil || defaults == nil {
		return ""
	}
	if cfg.Values["HOKUTO_CROSS_SYSTEM"] != "1" && cfg.Values["HOKUTO_CROSS_SIMPLE"] != "1" {
		return ""
	}
	prefix := defaults["CROSS_PREFIX"]
	if prefix == "" || prefix == "/usr" {
		return ""
	}
	return strings.TrimSuffix(prefix, "/")
}

// crossContainmentExemptPrefixes are the paths a cross,system package may write
// outside its sysroot: hokuto's own per-package bookkeeping, which is named
// after the prefixed package and so never collides with a native one.
var crossContainmentExemptPrefixes = []string{"/var/db/hokuto/"}

// verifyCrossSystemContainment refuses to package a cross,system build that
// staged files outside its sysroot.
func verifyCrossSystemContainment(outputDir, sysroot string) error {
	if sysroot == "" {
		return nil
	}
	var stray []string
	total := 0
	walkErr := filepath.WalkDir(outputDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(outputDir, path)
		if relErr != nil {
			return nil
		}
		abs := "/" + filepath.ToSlash(rel)
		if strings.HasPrefix(abs, sysroot+"/") {
			return nil
		}
		for _, exempt := range crossContainmentExemptPrefixes {
			if strings.HasPrefix(abs, exempt) {
				return nil
			}
		}
		total++
		if len(stray) < 10 {
			stray = append(stray, abs)
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("failed to inspect packaged output: %w", walkErr)
	}
	if total == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "cross,system build staged %d file(s) outside %s.\n", total, sysroot)
	fmt.Fprintf(&b, "Installing this package would overwrite host files with %s binaries.\n", filepath.Base(sysroot))
	for _, p := range stray {
		fmt.Fprintf(&b, "  %s\n", p)
	}
	if total > len(stray) {
		fmt.Fprintf(&b, "  ... and %d more\n", total-len(stray))
	}
	b.WriteString("The recipe most likely hardcodes a prefix; make it use \"$CROSS_PREFIX\"\n")
	b.WriteString("(or hokuto-meson / the generated cmake toolchain file, which already do).")
	return fmt.Errorf("%s", b.String())
}
