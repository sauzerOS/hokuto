package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildScriptIsCrossAwareIgnoresMultilibGuard(t *testing.T) {
	cases := []struct {
		name   string
		script string
		want   bool
	}{
		{
			// libva: the sole HOKUTO_CROSS reference only decides whether to
			// build the 32-bit split. The main build was never adapted.
			name: "multilib guard alone is not cross support",
			script: `#!/bin/bash -e
hokuto-meson build
meson compile -C build
meson install -C build --destdir=$1

if [ "${HOKUTO_CROSS:-0}" != "1" ] && [ "$MULTILIB" = "1" ]; then
rm -rf build
hokuto-meson-32 build
fi
`,
			want: false,
		},
		{
			// lm-sensors shape: a multilib guard *and* a real cross branch.
			name: "a genuine cross branch still counts",
			script: `#!/bin/bash -e
_tools=()
if [ "${HOKUTO_CROSS:-0}" = "1" ]; then
    _tools=(CC="$CC" AR="$AR")
fi
make "${_tools[@]}" PREFIX=/usr

if [ "${HOKUTO_CROSS:-0}" != "1" ] && [ "$MULTILIB" = "1" ]; then
make clean
fi
`,
			want: true,
		},
		{
			name: "CROSS_PREFIX always counts",
			script: `#!/bin/bash -e
cmake -D CMAKE_INSTALL_PREFIX="${CROSS_PREFIX:-/usr}" -B build
`,
			want: true,
		},
		{
			name: "no markers at all",
			script: `#!/bin/bash -e
./configure --prefix=/usr
make
`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "build")
			if err := os.WriteFile(p, []byte(tc.script), 0o755); err != nil {
				t.Fatal(err)
			}
			marker, got := buildScriptIsCrossAware(p)
			if got != tc.want {
				t.Fatalf("cross-aware = %v (marker %q), want %v", got, marker, tc.want)
			}
		})
	}
}
