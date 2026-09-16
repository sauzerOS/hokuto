package hokuto

import (
	"strings"
	"testing"
)

// The Raspberry Pi 4's Cortex-A72 lacks the optional ARMv8 Crypto Extensions,
// but -C target-cpu=cortex-a72 switches aes and sha2 on regardless. Crates that
// check features at compile time instead of at runtime then take the hardware
// path and die on the first sha256h, so the features have to come back off.
func TestBuildRustFlagsDisablesArmCryptoByDefault(t *testing.T) {
	cases := []string{
		"-O2 -march=armv8-a+crc -mcpu=cortex-a72 -pipe",
		"-O2 -march=armv8-a -pipe",
		"-O2 -march=cortex-a72",
	}
	for _, cflags := range cases {
		got := buildRustFlags(cflags, "", "/build", false)
		if !strings.Contains(got, "-C target-cpu=cortex-a72") {
			t.Errorf("cflags %q: lost the core selection: %s", cflags, got)
		}
		if !strings.Contains(got, "-aes") || !strings.Contains(got, "-sha2") {
			t.Errorf("cflags %q: crypto features not disabled: %s", cflags, got)
		}
	}
}

func TestBuildRustFlagsKeepsArmCryptoWhenTheCPUHasIt(t *testing.T) {
	// CPU_FLAGS naming crypto means the target really does implement it.
	for _, flags := range []string{"crypto", "aes sha2", "neon crc sha1"} {
		got := buildRustFlags("-O2 -march=armv8-a+crypto+crc", flags, "/build", false)
		if strings.Contains(got, "-aes") || strings.Contains(got, "-sha2") {
			t.Errorf("cpuFlags %q: crypto disabled even though the CPU has it: %s", flags, got)
		}
	}
}

func TestBuildRustFlagsLeavesX86Alone(t *testing.T) {
	got := buildRustFlags("-O2 -march=x86-64-v3 -pipe", "avx2 fma", "/build", false)
	if strings.Contains(got, "-aes") || strings.Contains(got, "-sha2") {
		t.Errorf("x86 flags picked up the ARM crypto workaround: %s", got)
	}
	if !strings.Contains(got, "-C target-cpu=x86-64-v3") {
		t.Errorf("x86 target-cpu lost: %s", got)
	}
}

func TestBuildRustFlagsGenericStaysGeneric(t *testing.T) {
	got := buildRustFlags("-O2 -march=armv8-a+crc -mcpu=cortex-a72", "", "/build", true)
	if strings.Contains(got, "target-cpu") || strings.Contains(got, "target-feature") {
		t.Errorf("generic build should carry no tuning: %s", got)
	}
}

func TestDisableUnavailableArmCrypto(t *testing.T) {
	tests := []struct {
		name     string
		cpuFlags string
		isARM    bool
		want     bool // expect the features to be disabled
	}{
		{"arm without crypto", "", true, true},
		{"arm with unrelated flags", "neon crc", true, true},
		{"arm with crypto", "crypto", true, false},
		{"arm with aes", "aes", true, false},
		{"arm with sha2", "sha2", true, false},
		{"not arm", "", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := disableUnavailableArmCrypto("BASE", tc.cpuFlags, tc.isARM)
			disabled := strings.Contains(got, "-aes,-sha2")
			if disabled != tc.want {
				t.Errorf("disabled = %v, want %v (got %q)", disabled, tc.want, got)
			}
			if !strings.Contains(got, "BASE") {
				t.Errorf("existing flags dropped: %q", got)
			}
		})
	}
}

func TestSuggestCFLAGSNeverAssumesArmCrypto(t *testing.T) {
	// Whatever this machine is, the arm64 string must not claim crypto unless
	// the CPU reports both aes and sha2.
	features := readARMFeatures()
	out := SuggestCFLAGS()
	if !strings.Contains(out, "armv8") {
		t.Skip("not an arm64 host")
	}
	hasCrypto := features["aes"] && features["sha2"]
	if strings.Contains(out, "+crypto") && !hasCrypto {
		t.Errorf("suggested +crypto on a CPU without it: %s", out)
	}
}
