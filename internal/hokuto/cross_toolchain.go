package hokuto

import "sync"

// A recipe that cross builds with a toolchain names two packages of the same
// recipe: the native host tool and the cross package of its target runtime,
// as blake3 does with "rust cross make" and "aarch64-rust cross make". The
// two must be the same release: rustc loads only the standard library it
// built itself. A build dependency may fall back to an older binary while the
// current one is not published yet (availableBuildDependencyBinaryTarball);
// for such a cross package an older binary only qualifies when its version is
// the native host tool's. Otherwise the cross package is built first.

// crossToolchainPairs maps a cross package (aarch64-rust) to the native host
// tool of the same recipe (rust) that one build uses together with it.
var crossToolchainPairs sync.Map

// noteCrossToolchainPairs records the pairs a recipe's dependency list names
// in a cross session: a bare cross dependency (the host tool) next to the
// prefixed package of the same name.
func noteCrossToolchainPairs(deps []DepSpec, cfg *Config) {
	if cfg == nil || cfg.Values["HOKUTO_CROSS_ARCH"] == "" {
		return
	}
	hostTools := make(map[string]bool)
	for _, dep := range deps {
		if dep.Cross && dep.Name != "" && archPrefixOf(dep.Name) == "" {
			hostTools[dep.Name] = true
		}
	}
	for _, dep := range deps {
		prefix := archPrefixOf(dep.Name)
		if prefix == "" {
			continue
		}
		if native := dep.Name[len(prefix):]; hostTools[native] {
			crossToolchainPairs.Store(dep.Name, native)
		}
	}
}

// crossToolchainVersion returns the version an older binary of pkgName must
// have to be used, or "" when any older one will do: pkgName is not paired
// with a host tool, or the host tool's version is not known yet. That is the
// installed native package's version or, while it is not installed, the
// current one if its binary is published (the one that will be installed).
func crossToolchainVersion(pkgName string, cfg *Config, noRemote bool) string {
	value, ok := crossToolchainPairs.Load(pkgName)
	if !ok {
		return ""
	}
	native := value.(string)
	if version, installed := getInstalledVersion(native); installed {
		return version
	}
	if dependencyBinaryAvailable(native, nativeConfig(cfg), noRemote) {
		if version, _, err := getRepoVersion2(native); err == nil {
			return version
		}
	}
	return ""
}

// crossToolchainBinaryUnusable reports whether pkgName is paired with a host
// tool and no binary of it has that tool's version, so it will be built:
// dependency resolution must then walk what building it needs (aarch64-rust
// 1.98.1 exists next to rust 1.99.0; building aarch64-rust needs
// aarch64-llvm).
func crossToolchainBinaryUnusable(pkgName string, cfg *Config, noRemote bool) bool {
	if crossToolchainVersion(pkgName, cfg, noRemote) == "" {
		return false
	}
	_, ok, err := locateBuildDependencyBinaryTarball(pkgName, cfg, noRemote)
	return err == nil && !ok
}
