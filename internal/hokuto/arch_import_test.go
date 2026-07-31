package hokuto

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestImportedPackageMetadataWrittenWithoutPrompts(t *testing.T) {
	pkgbuild := `
pkgbase=demo
pkgname=(demo demo-tools)
pkgver=1.2.3
pkgdesc='Imported package description'
url='https://example.com/demo'
_primary_license=GPL-3.0-or-later
license=("$_primary_license" MIT)

package_demo() {
    make DESTDIR="$pkgdir" install
}

package_demo_tools() {
    make DESTDIR="$pkgdir" install-tools
}
`
	info, err := parsePKGBUILD(pkgbuild, "demo")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		source     string
		repository string
		category   string
	}{
		{name: "arch", source: "Arch", repository: "core", category: "base"},
		{name: "aur", source: "AUR", category: "extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgDir := t.TempDir()
			if err := writeImportedPackageMetadata(pkgDir, info, tt.source, tt.repository); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(pkgDir, "metadata.json"))
			if err != nil {
				t.Fatal(err)
			}
			var metadata PackageMetadata
			if err := json.Unmarshal(data, &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata.URL != "https://example.com/demo" || metadata.Description != "Imported package description" {
				t.Fatalf("PKGBUILD metadata was not preserved: %+v", metadata)
			}
			if metadata.License != "GPL-3.0-or-later, MIT" || metadata.Category != tt.category {
				t.Fatalf("unexpected imported license/category: %+v", metadata)
			}
			if metadata.Info != "" || len(metadata.Tags) != 0 {
				t.Fatalf("info and tags must default to empty: %+v", metadata)
			}
			if !strings.Contains(string(data), `"info": ""`) || !strings.Contains(string(data), `"tags": []`) {
				t.Fatalf("metadata.json must explicitly contain empty info and tags: %s", data)
			}
			if !reflect.DeepEqual(metadata.Subpackages, []string{"demo-tools"}) {
				t.Fatalf("unexpected imported subpackages: %v", metadata.Subpackages)
			}
		})
	}
}

func TestParsePKGBUILDExpandsDependencyBraces(t *testing.T) {
	pkgbuild := `
_pyname=fontPens
pkgname=python-${_pyname,,}
pkgver=0.4.0
_archive="${_pyname,,}-$pkgver"
depends=(python-fonttools)
makedepends=(python-{build,installer,wheel}
             python-hatch-vcs
             python-hatchling)
source=("https://files.pythonhosted.org/packages/source/${_pyname::1}/$_pyname/$_archive.tar.gz")
`
	info, err := parsePKGBUILD(pkgbuild, "python-fontpens")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"python-build", "python-installer", "python-wheel", "python-hatch-vcs", "python-hatchling"}
	if !reflect.DeepEqual(info.MakeDepends, want) {
		t.Fatalf("unexpected expanded make dependencies: got %v want %v", info.MakeDepends, want)
	}
	wantSource := "https://files.pythonhosted.org/packages/source/f/fontPens/fontpens-0.4.0.tar.gz"
	if len(info.Sources) != 1 || info.Sources[0] != wantSource {
		t.Fatalf("unexpected case-modified source: got %v want %q", info.Sources, wantSource)
	}
}

func TestExpandBashBraceWordSupportsEmptyAndMultipleGroups(t *testing.T) {
	want := []string{"source.tar", "source.tar.sig"}
	if got := expandBashBraceWord("source.tar{,.sig}"); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected empty-choice expansion: got %v want %v", got, want)
	}
	want = []string{"python-build-a", "python-build-b", "python-wheel-a", "python-wheel-b"}
	if got := expandBashBraceWord("python-{build,wheel}-{a,b}"); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected Cartesian expansion: got %v want %v", got, want)
	}
}

func TestParsePKGBUILDConcatenatesQuotedSourceWithBraceExpansion(t *testing.T) {
	pkgbuild := `
pkgbase=php
pkgname=(php php-cgi)
pkgver=8.5.9
source=("https://php.net/distributions/${pkgbase}-${pkgver}.tar.xz"{,.asc}
        'apache.patch')
`
	info, err := parsePKGBUILD(pkgbuild, "php")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://php.net/distributions/php-${version}.tar.xz",
		"https://php.net/distributions/php-${version}.tar.xz.asc",
		"apache.patch",
	}
	if !reflect.DeepEqual(info.Sources, want) {
		t.Fatalf("unexpected PHP sources: got %v want %v", info.Sources, want)
	}
}

func TestAtomicPackageImportCleansUpFailedImport(t *testing.T) {
	parentDir := t.TempDir()
	pkgDir := filepath.Join(parentDir, "php")
	populateErr := errors.New("source download failed")
	err := atomicPackageImport(pkgDir, "php", func(importDir string) error {
		if err := os.WriteFile(filepath.Join(importDir, "partial"), []byte("partial"), 0o644); err != nil {
			return err
		}
		return populateErr
	})
	if !errors.Is(err, populateErr) {
		t.Fatalf("unexpected import error: %v", err)
	}
	if _, err := os.Stat(pkgDir); !os.IsNotExist(err) {
		t.Fatalf("failed import left its final package directory behind: %v", err)
	}
	entries, err := os.ReadDir(parentDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed import left temporary files behind: %v", entries)
	}
}

func TestAtomicPackageImportPublishesCompletedImport(t *testing.T) {
	pkgDir := filepath.Join(t.TempDir(), "php")
	if err := atomicPackageImport(pkgDir, "php", func(importDir string) error {
		return os.WriteFile(filepath.Join(importDir, "version"), []byte("8.5.9 1\n"), 0o644)
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(pkgDir, "version"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "8.5.9 1\n" {
		t.Fatalf("unexpected published contents: %q", data)
	}
}

func TestImportFuzzySearchOnlyForNotFoundErrors(t *testing.T) {
	if !isImportPackageNotFound(fmt.Errorf("fetch failed: %w", errImportPackageNotFound)) {
		t.Fatal("wrapped not-found error should permit fuzzy search")
	}
	if isImportPackageNotFound(errors.New("failed to parse PKGBUILD")) {
		t.Fatal("conversion errors must not permit fuzzy search")
	}
}

func TestParsePKGBUILDPreservesPrepareAndSplitFunctions(t *testing.T) {
	pkgbuild := `
pkgname=(demo demo-libs)
pkgver=1.2.3
depends=('glibc')
makedepends=('cmake')

prepare() {
    cd "$srcdir/demo"
    if true; then
        patch -Np1 < ../fix.patch
    fi
}

build() {
    make
}

package_demo() {
    depends=('demo-libs' 'glibc')
    make DESTDIR="$pkgdir" install-bin
}

package_demo_libs() {
    make DESTDIR="$pkgdir" install-libs
}
`
	info, err := parsePKGBUILD(pkgbuild, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(info.PrepareFunc, "cd ") || strings.Contains(info.PrepareFunc, "\n    cd ") {
		t.Fatalf("prepare function was not preserved and dedented: %q", info.PrepareFunc)
	}
	if info.BuildFunc != "make" {
		t.Fatalf("unexpected build function: %q", info.BuildFunc)
	}
	if len(info.SplitFuncs) != 1 || info.SplitFuncs[0].Package != "demo-libs" || !strings.Contains(info.PackageFunc, "install-bin") {
		t.Fatalf("unexpected split functions: %+v", info.SplitFuncs)
	}
	if strings.Join(info.Depends, ",") != "demo-libs,glibc" {
		t.Fatalf("primary package dependencies were not retained: %v", info.Depends)
	}

	script := generateBuildScript(info, "demo")
	if strings.Index(script, "# Prepare phase") > strings.Index(script, "# Build phase") {
		t.Fatal("prepare phase must precede build phase")
	}
	if !strings.Contains(script, `make DESTDIR="${HOKUTO_SPLIT_DIR}/demo-libs" install-libs`) {
		t.Fatalf("split output was not translated: %s", script)
	}
	if strings.Contains(script, "\n    make") {
		t.Fatalf("top-level commands remain indented: %s", script)
	}
	if strings.Contains(script, "depends=(") {
		t.Fatalf("split metadata leaked into executable build script: %s", script)
	}
}

func TestParsePKGBUILDDoesNotTreatSubstringExpansionAsSourceRename(t *testing.T) {
	pkgbuild := `
pkgbase=pyxdg
pkgname=python-pyxdg
pkgver=0.28
source=("https://files.pythonhosted.org/packages/source/${pkgbase::1}/${pkgbase}/${pkgbase}-${pkgver}.tar.gz"
        pyxdg-python3.14.patch)
package() { make DESTDIR="$pkgdir" install; }
`
	info, err := parsePKGBUILD(pkgbuild, "python-pyxdg")
	if err != nil {
		t.Fatal(err)
	}
	wantURL := "https://files.pythonhosted.org/packages/source/p/pyxdg/pyxdg-${version}.tar.gz"
	if len(info.Sources) != 2 || info.Sources[0] != wantURL || info.Sources[1] != "pyxdg-python3.14.patch" {
		t.Fatalf("unexpected converted sources: %v", info.Sources)
	}
	if _, _, renamed := splitArchRenamedSource("${pkgbase::1}/${pkgbase}.tar.gz"); renamed {
		t.Fatal("substring expansion was treated as an Arch renamed source")
	}
	fileURL, err := archPackageFileURL("pyxdg", "Arch", "pyxdg-python3.14.patch")
	if err != nil || !strings.HasSuffix(fileURL, "/pyxdg-python3.14.patch") {
		t.Fatalf("unexpected package file URL %q: %v", fileURL, err)
	}
}

func TestParsePKGBUILDResolvesChainedPrivateVariables(t *testing.T) {
	pkgbuild := `
pkgname=qt6-webengine
_pkgver=6.10.0-beta3
pkgver=${_pkgver/-/}
_pkgfn=qtwebengine-everywhere-src-$_pkgver
source=("git+https://code.qt.io/qt/$_pkgfn#tag=v$_pkgver"
        git+https://code.qt.io/qt/qtwebengine-chromium)
build() {
    cd $_pkgfn
    cmake -B build -S $_pkgfn
}
package() {
    DESTDIR="$pkgdir" cmake --install build
}
`
	info, err := parsePKGBUILD(pkgbuild, "qt6-webengine")
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "6.10.0beta3" {
		t.Fatalf("unexpected resolved version: %q", info.Version)
	}
	wantSource := "git+https://code.qt.io/qt/qtwebengine-everywhere-src-6.10.0-beta3#tag=v6.10.0-beta3"
	if len(info.Sources) != 2 || info.Sources[0] != wantSource {
		t.Fatalf("unexpected resolved sources: %v", info.Sources)
	}
	if strings.Contains(info.BuildFunc, "$_pkg") || !strings.Contains(info.BuildFunc, "cd qtwebengine-everywhere-src-6.10.0-beta3") {
		t.Fatalf("private variables were not resolved in build function: %q", info.BuildFunc)
	}
}
