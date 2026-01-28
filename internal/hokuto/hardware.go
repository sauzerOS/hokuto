package hokuto

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
)

// CPUFlagMap maps /proc/cpuinfo flag names to Hokuto/Gentoo standard names
var CPUFlagMap = map[string]string{
	// x86
	"mmx":        "mmx",
	"sse":        "sse",
	"sse2":       "sse2",
	"pni":        "sse3",
	"ssse3":      "ssse3",
	"sse4_1":     "sse4_1",
	"sse4_2":     "sse4_2",
	"avx":        "avx",
	"avx2":       "avx2",
	"avx512f":    "avx512f",
	"avx512dq":   "avx512dq",
	"avx512ifma": "avx512ifma",
	"avx512cd":   "avx512cd",
	"avx512bw":   "avx512bw",
	"avx512vl":   "avx512vl",
	"fma":        "fma",
	"aes":        "aes",
	"pclmulqdq":  "pclmul",
	"popcnt":     "popcnt",
	"sha_ni":     "sha",
	// ARM64
	"fp":    "fp",
	"asimd": "asimd",
	"crc32": "crc32",
	"sha1":  "sha1",
	"sha2":  "sha2",
}

// SuggestCFLAGS returns a string of optimized CFLAGS base on detected hardware
func SuggestCFLAGS() string {
	arch := runtime.GOARCH
	if arch == "amd64" {
		// Detect specific x86-64 level or micro-arch
		march := "x86-64-v3" // Default to v3 (AVX2 era) if we detect AVX2

		flags := make(map[string]bool)
		file, err := os.Open("/proc/cpuinfo")
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "flags") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) >= 2 {
						for _, f := range strings.Fields(parts[1]) {
							flags[f] = true
						}
					}
					break
				}
			}
		}

		if flags["avx512f"] {
			march = "x86-64-v4"
		} else if flags["avx2"] {
			march = "x86-64-v3"
		} else if flags["sse4_2"] {
			march = "x86-64-v2"
		}

		return fmt.Sprintf("-O2 -march=%s -mtune=generic -pipe", march)
	} else if arch == "arm64" {
		return "-O2 -march=armv8-a+crypto+crc -mtune=generic -pipe"
	}
	return "-O2 -pipe"
}

// DetectCPUFlags returns a string of detected hardware flags
func DetectCPUFlags() string {
	flags := make(map[string]bool)

	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "flags") || strings.HasPrefix(line, "Features") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				continue
			}
			rawFlags := strings.Fields(parts[1])
			for _, f := range rawFlags {
				if renamed, ok := CPUFlagMap[f]; ok {
					flags[renamed] = true
				}
			}
			// Only need to scan the first processor entry
			break
		}
	}

	var result []string
	for f := range flags {
		result = append(result, f)
	}
	sort.Strings(result)
	return strings.Join(result, " ")
}
