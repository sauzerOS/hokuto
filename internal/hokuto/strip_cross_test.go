package hokuto

import "testing"

// Cross builds emit target binaries, so they need the cross toolchain's strip.
// hokuto used to skip stripping entirely for them, on the theory that the host
// strip could not read the output -- true, but the fix is to use the right
// strip, not to ship debug info. An unstripped libxul.so is 2.6GB against
// 114MB of .text.
func TestStripBinarySelection(t *testing.T) {
	cfgWith := func(kv map[string]string) *Config {
		values := map[string]string{}
		for k, v := range kv {
			values[k] = v
		}
		return &Config{Values: values}
	}

	for _, tc := range []struct {
		name    string
		cfg     *Config
		options map[string]bool
		want    string
	}{
		{
			name: "native build uses the host strip",
			cfg:  cfgWith(nil),
			want: "strip",
		},
		{
			name: "nil config falls back to the host strip",
			cfg:  nil,
			want: "strip",
		},
		{
			name: "plain cross build strips target binaries",
			cfg:  cfgWith(map[string]string{"HOKUTO_CROSS_ARCH": "arm64"}),
			want: "aarch64-linux-gnu-strip",
		},
		{
			name: "arch name is normalized",
			cfg:  cfgWith(map[string]string{"HOKUTO_CROSS_ARCH": "aarch64"}),
			want: "aarch64-linux-gnu-strip",
		},
		{
			name: "cross-system sysroot packages are target binaries too",
			cfg: cfgWith(map[string]string{
				"HOKUTO_CROSS_ARCH":   "arm64",
				"HOKUTO_CROSS_SYSTEM": "1",
			}),
			want: "aarch64-linux-gnu-strip",
		},
		{
			name: "cross-simple keeps the native toolchain, so the host strip",
			cfg: cfgWith(map[string]string{
				"HOKUTO_CROSS_ARCH":   "arm64",
				"HOKUTO_CROSS_SIMPLE": "1",
			}),
			want: "strip",
		},
		{
			name: "a host-tool under cross-system builds for the build machine",
			cfg: cfgWith(map[string]string{
				"HOKUTO_CROSS_ARCH":   "arm64",
				"HOKUTO_CROSS_SYSTEM": "1",
			}),
			options: map[string]bool{"host-tool": true},
			want:    "strip",
		},
		{
			name:    "a host-tool in a plain cross build still produces target binaries",
			cfg:     cfgWith(map[string]string{"HOKUTO_CROSS_ARCH": "arm64"}),
			options: map[string]bool{"host-tool": true},
			want:    "aarch64-linux-gnu-strip",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripBinary(tc.cfg, tc.options); got != tc.want {
				t.Errorf("stripBinary() = %q, want %q", got, tc.want)
			}
		})
	}
}
