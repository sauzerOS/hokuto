package hokuto

import (
	"reflect"
	"strings"
	"testing"
)

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
