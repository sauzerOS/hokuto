# Hokuto source guide for AI agents

This file is the starting point for work in this repository. Read it before
changing package-management behavior. It describes the current implementation,
the places where similar-looking workflows diverge, and the invariants that
recent regressions have tended to violate.

## What Hokuto is

Hokuto is the sauzerOS package manager. It is a Go CLI that:

- reads source package recipes from one or more repositories in `HOKUTO_PATH`;
- resolves source, binary, split, optional, constrained, and alternative
  dependencies;
- builds signed `.tar.zst` packages;
- installs packages through a staging area while preserving manifests and
  user-modified files;
- updates source repositories and installed packages;
- maintains a local installed-package database, world files, metadata database,
  alternatives, rebuild triggers, and binary-mirror indexes.

The user-facing packaging guide is
`/home/dbz/Documents/sauzerOS.github.io/hokuto.html`. It is useful background,
especially for recipe syntax, but source code is authoritative when the guide
and implementation differ.

## Fast orientation

The executable is `cmd/hokuto/main.go`, which calls `internal/hokuto.Main()`.
Almost all code is in the single Go package `hokuto` under `internal/hokuto`.
There are intentionally many package-level globals, so tests and parallel code
must isolate or restore global state carefully.

Start with these files:

| Concern | Primary files |
| --- | --- |
| Startup, flags, command dispatch | `cli.go`, `privilege.go`, `executor.go` |
| Configuration and global paths | `config.go`, `globals.go` |
| Package/source lookup | `pkgdb.go`, `deps.go` |
| Build planning and execution | `deps.go`, `build.go`, `parallel.go` |
| Source fetching and verification | `fetch.go`, `checksum.go`, `pkgops.go` |
| Archive creation and naming | `archive.go`, `index.go`, `sign.go` |
| Installation and upgrades | `install.go`, `staging.go`, `manifest.go`, `update.go` |
| Remote packages and indexes | `query.go`, `fetch.go`, `update_remote.go`, `mirror.go` |
| Installed state and cleanup | `world.go`, `uninstall.go`, `cleanup.go` |
| Split packages | `deps.go`, `build.go`, `update.go`, `meta.go` |
| Metadata/search | `meta.go`, `meta_build.go`, `package_info.go` |
| Alternatives | `alternatives.go`, `alternatives_tui.go` |
| Developer/package author commands | `pkgdev.go`, `pkgset.go`, `arch_import.go`, `upload.go` |
| Repository setup and LFS | `repos.go`, `update.go` |
| TUI and prompts | `tui.go`, `interaction.go`, `prompt.go`, `parallel.go` |

Use `rg` before broad reading. Useful searches include:

```sh
rg -n 'case "build"|case "install"|case "update"' internal/hokuto/cli.go
rg -n '^func handleBuildCommand|^func pkgBuild' internal/hokuto/build.go
rg -n '^func resolveBuildPlan|^func resolveMissingDeps' internal/hokuto/deps.go
rg -n '^func pkgInstall|^func pkgInstallWithRemotePolicy' internal/hokuto/install.go
rg -n '^func checkForUpgrades|^func prepareUpdateBuildPlan' internal/hokuto/update.go
rg -n '^func RunParallelBuilds|^func \\(pm \\*ParallelManager\\)' internal/hokuto/parallel.go
```

## Startup, configuration, and privilege model

`Main()` in `cli.go` performs this order:

1. Create the cancellation context and signal handler.
2. Load `hokuto.conf`; `HOKUTO_ROOT` changes the config path.
3. Merge `HOKUTO_*` environment overrides and call `initConfig`.
4. Determine whether the command needs root privileges.
5. Authenticate once through sudo or run0.
6. Resolve supported `pkg@version` arguments from Git history.
7. Initialize `UserExec` and `RootExec`.
8. Dispatch the command.

`Config.Values` is the runtime configuration map. `initConfig` derives global
paths such as:

- `SourcesDir = $HOKUTO_CACHE_DIR/sources`
- `BinDir = $HOKUTO_CACHE_DIR/bin`
- `Installed = $HOKUTO_ROOT/var/db/hokuto/installed`
- `WorldFile = $HOKUTO_ROOT/var/db/hokuto/world`
- `WorldMakeFile = $HOKUTO_ROOT/var/db/hokuto/world_make`
- `PkgDBPath = $HOKUTO_ROOT/var/db/hokuto/pkg-db.json.zst`

Do not construct target-root paths independently if an existing initialized
global or helper covers them. `filepath.Join(rootDir, "/absolute-looking/path")`
is used deliberately in this codebase.

Use `Executor.Run` for commands that need Hokuto's cancellation, stdio,
privilege, process-group, and idle-priority behavior. `UserExec` runs as the
invoking user; `RootExec` uses the selected privilege backend. Installation
sets `isCriticalAtomic` so the first interrupt does not leave the filesystem
half-mutated.

## Package identities: do not collapse these concepts

A package can have several related names:

- **source package**: directory name under `HOKUTO_PATH`;
- **split package**: output produced by a source package;
- **output/install name**: may gain an architecture prefix for cross-system
  builds;
- **archive/index name**: stable canonical identity used in tarball names and
  remote indexes;
- **historical parallel name**: internal `pkg-MAJOR` identity used to install
  constrained versions alongside the current package.

Relevant helpers:

- `findPackageMetadataDir` performs cheap lookup and prefers repositories, then
  installed metadata.
- `findPackageDir` may derive/extract historical package sources.
- `findSplitPackageSource` and `findSplitDependencySource` map split outputs to
  their source.
- `getOutputPackageName`, `getArchivePackageName`,
  `canonicalParallelPackageName`, and `sameSourcePackage` preserve the
  distinctions above.

Do not use `filepath.Base(pkgDir)` as a universal package identity, and do not
assume a requested split package has its own source directory.

## Recipe format

A normal recipe directory may contain:

- `version`: `<version> <revision>`;
- `build`: executable shell build instructions;
- `.sources`: source template used by bumping;
- `sources`: resolved source URLs;
- `checksums`: BLAKE3 checksums for non-Git sources;
- `depends` and `depends.<split>`;
- `options` and limited `options.<split>` overrides;
- `split` script and/or `split/<name>/depends`;
- `files`: local recipe files;
- `post-install` and `post-install.split`;
- `libdeps.ignore` and `libdeps.ignore.<split>`;
- `metadata.json`.

The `build` script receives:

- `$1`: output/DESTDIR;
- `$2`: version;
- `$3`: package name.

Important environment variables include `HOKUTO_ARCH`, `HOKUTO_ROOT`,
`HOKUTO_BUILD_DIR`, `HOKUTO_OUTPUT_DIR`, `HOKUTO_SPLIT_DIR`, `HOKUTO_LTO`,
`HOKUTO_GENERIC`, `HOKUTO_CROSS`, `HOKUTO_CARCH`, `MULTILIB`, `TMPDIR`,
compiler/linker flags, Cargo/Go cache locations, and parallel-build variables.
See the environment assembly in `pkgBuild` for the exact current set.

Git sources use a shared mirror/checkout cache implemented in `fetch.go`.
Full-history Git sources can use the internal go-git fallback; shallow sources
require system Git. Source filename overrides use `URL -> filename`.

### Dependency flags

`DepSpec` and `parseDependsData` in `index.go` define dependency syntax.
Common forms:

- `pkg`: normal required dependency;
- `pkg make`: build-only dependency;
- `pkg runtime`: runtime-only dependency;
- `pkg optional`: build with it when available, then track/rebuild the parent;
- `pkg rebuild`: post-build rebuild action when `--rebuilds` is enabled;
- `pkg suggest "text"`: user-facing suggestion;
- `pkg cross make` and cross-native variants;
- `a | b`: alternatives;
- `pkg==1.*`, `pkg<=2.0`, etc.: constraints, potentially resolved from Git
  history.

Archive dependency metadata can differ from source recipe dependencies because
Hokuto generates runtime shared-library dependencies. When installing a binary,
the archive's packaged metadata is authoritative. Do not traverse source-only
make dependencies for a confirmed binary target.

### Build options

`loadBuildOptions` in `build.go` reads whitespace-separated tags from
`options`. Important tags include:

- `asroot`, `interactive`, `noram`, `idle`;
- `binary`, `nodevel`, `devel`;
- `multilib`, `generic`;
- `nolto`, `nostrip`, `staticlibs`, `clang`;
- `cross-simple`, `host-tool`, `nocrossopt`.

Base-devel policy is centralized by `packageNeedsDevelPackages`:

```text
devel || (!binary && !nodevel)
```

`multilib` expands the toolchain set. Any new path that builds packages must
honor this policy. Split `options.<name>` files currently support only the
post-build `nostrip`/`staticlibs` overrides, including `!option` removal; do not
silently treat them as full parent option files.

## Dependency resolution

There are multiple resolvers for different jobs. Do not substitute one merely
because it returns package names.

- `resolveBuildPlan` creates a `BuildPlan` for source builds. It handles graph
  order, binaries, optional rebuilds, explicit rebuilds, manual prerequisites,
  split outputs, and constrained packages.
- `resolveMissingDeps` finds dependencies that are not currently satisfied and
  is used by build-dependency installation and related workflows.
- `resolveBinaryDependenciesFromArchive` reads dependency metadata from cached
  or remote archives.
- `resolveRemoteDependencies` is for remote-only planning.

`BuildPlan` is the shared contract between resolution and execution:

- `Order`: build/install order;
- `RebuildPackages`: force source rebuild instead of accepting installed/binary;
- `PostRebuilds`: optional-dependency parent rebuilds;
- `PostBuildRebuilds`: explicit trigger-after-package actions;
- `ManualPrereqs`: order imposed by `hokuto.update`;
- `BinaryPackages`: archive metadata replaces source dependency traversal;
- `NoDeps` and `NoInstall`: execution controls.

When a new field or dependency class is added, update both sequential execution
and `ParallelManager.canBuild`; otherwise `-j1` and `-jN` will disagree.

## Build flow

`handleBuildCommand` is the full command orchestrator. It:

1. parses flags and sets build/cross/bootstrap policy;
2. normalizes source, split, metapackage, and versioned targets;
3. resolves missing dependencies and available binaries;
4. installs base-devel and temporary build dependencies;
5. builds a `BuildPlan`;
6. executes sequentially or through `RunParallelBuilds`;
7. installs intermediate dependencies and optionally final targets;
8. runs rebuild actions and cleanup.

`pkgBuild` is a lower-level primitive for one already-prepared package. It does
not replace the command orchestration. Calling `pkgBuild` directly is correct
inside an existing prepared plan, dependency fallback, or dedicated rebuild
path. It is usually wrong for a new top-level command because it bypasses
base-devel preparation, dependency planning, temporary cleanup, split-target
mapping, and other refactored behavior.

For example, `hokuto bump --build` delegates back to `handleBuildCommand` with
idle/no-install/index flags rather than assembling a partial build flow.

Inside `pkgBuild`:

1. clone `Config` to prevent parallel builds leaking per-package changes;
2. find the recipe and load options/version;
3. reserve a unique temporary tree (`build`, `output`, `split`, `log`);
4. fetch and verify sources;
5. copy/unpack sources into the build directory;
6. construct architecture/compiler/cross/LTO environment;
7. execute the recipe and capture the build log;
8. run split packaging;
9. finalize the parent output.

Finalization generates runtime dependencies, copies recipe metadata and hooks,
cleans/strips output, writes package info and manifest, signs the package, and
creates the archive in `BinDir`.

## Split packages

Split outputs are discovered from `depends.<name>` and
`split/<name>/depends`. A request for a split output schedules its source
package and records which output is actually required.

Keep these rules intact:

- building a source package can satisfy several split dependencies;
- installing a requested split output must not implicitly install the parent
  output unless the parent was requested/needed;
- a parent binary does not satisfy a missing split output;
- split dependency availability must be published to parallel scheduling;
- split metadata inherits parent `metadata.json` fields and applies explicit
  overrides;
- split packages use `post-install.<split>` when present, otherwise the shared
  `post-install.split`; the parent `post-install` is not inherited implicitly.

Changes involving split packages should be tested in build, install, and update
paths, not only in package creation.

## Install flow

The CLI builds an install plan first, using archive metadata when a binary is
selected. Explicitly requested packages are tracked separately so only they are
added to `world`.

`pkgInstallWithRemotePolicy` is the main installer:

1. unpack the archive into a temporary staging tree;
2. verify signature/integrity;
3. inspect installed manifests and preserve or prompt for modified files;
4. detect file conflicts and alternatives;
5. calculate obsolete files;
6. detect removed/upgraded libraries and back them up;
7. rsync staging into `HOKUTO_ROOT`;
8. remove obsolete files;
9. execute package post-install and ensure runtime dependencies;
10. discover rebuild triggers/affected reverse dependencies;
11. update installed metadata, suggestions, and global post-install state.

The `managed` argument means a caller such as parallel update owns rebuild
scheduling. In managed mode the installer returns rebuild targets rather than
building them inline.

Manifests are the basis for ownership, integrity, uninstall, modified-file
handling, and conflicts. Preserve whitespace in manifest paths and use
canonical ownership helpers so `/bin` versus `/usr/bin` aliases and active
alternatives remain correct.

## Update and parallel execution

`checkForUpgrades` in `update.go` is the main local update workflow:

1. determine installed/repository versions and selected updates;
2. normalize split targets;
3. check/fetch available binaries;
4. snapshot installed packages for temporary-dependency cleanup;
5. resolve and repeatedly refine the build plan as binary dependencies install;
6. prepare base-devel only if source builds remain;
7. execute sequentially or with `RunParallelBuilds`;
8. perform post-install work and remove packages installed only for the update.

`ParallelManager` owns pending/running/completed/available/failed state. It
installs successful dependencies before releasing their dependents. It must
publish split outputs separately from their source package.

Some rebuilds are discovered only while installing an updated package:

- `/etc/hokuto/hokuto.rebuild` triggers;
- removed/upgraded shared-library reverse dependencies;
- configured kernel-module and automatic Perl-module triggers;
- optional dependencies becoming available.

These packages were not necessarily in the original plan. Dynamically
discovered rebuilds must prepare their own base-devel and recipe build
dependencies before entering the parallel queue. Track and display the package
that triggered each rebuild. Planned optional/post-build rebuilds already had
their dependencies resolved and should not repeat preparation.

Whenever adding dynamic work, check all of the following:

- Is it marked in `RebuildPackages` so cached binaries are not reused?
- Are its build dependencies installed?
- Does `canBuild` see those dependencies as available?
- Will temporary installs be cleaned?
- Is the triggering reason visible?
- Can it override an earlier completed binary when that binary is now stale?

## Installed state, world files, and cleanup

Installed package metadata lives under
`$HOKUTO_ROOT/var/db/hokuto/installed/<name>`. Do not infer installation only
from filesystem payloads; use `isPackageInstalled`,
`checkPackageExactMatch`, version helpers, and metapackage helpers.

`world` records explicit runtime selections. `world_make` records persistent
make dependencies. Temporary dependencies must not become ordinary world
packages. Orphan calculation combines world roots, installed dependency
metadata, metapackages, suggestions, and make roots.

Build/update cleanup deliberately snapshots preexisting packages and removes
only dependencies introduced by that operation. Preserve this boundary on
errors as well as success. Build-session tracking prevents cleanup from racing
other Hokuto builds.

## Binary archives, mirrors, and metadata

Archive names follow:

```text
<name>-<version>-<revision>-<arch>-<variant>.tar.zst
```

Use `StandardizeRemoteName` rather than formatting names manually. Architecture
and variant selection is centralized in `index.go`. Variants distinguish local,
generic, multilib, and cross-system outputs.

Remote index access is cached globally through `GetCachedRemoteIndex`.
Signature verification and package signing are in `sign.go`; keyring fetching
is in `keyring.go`. Avoid bypassing verification in a new install path.

`metadata.json` is human-facing package metadata. `meta.go` creates the
compressed global package database used by info/search, including split
inheritance. It is separate from archive `.PKGINFO` and installed dependency
metadata.

## Package development commands

`pkgdev.go` contains `new`, `edit`, `bump`, Repology auto-bump, Git commit/push,
and optional repository bump logic. `pkgset.go` reads batch sets.

Bumping modifies `version`, expands `.sources` into `sources`, fetches sources,
updates checksums, commits, pushes, optionally builds through the normal build
orchestrator, refreshes the package database, and syncs uploads.

Treat Git push, upload, repository initialization, and metadata publication as
external side effects. A request to diagnose or review does not authorize them.

## Testing and validation

Run formatting on touched Go files:

```sh
gofmt -w internal/hokuto/file.go
```

Run the full suite:

```sh
go test ./...
```

If the normal Go cache is not writable in a sandbox:

```sh
GOCACHE=/tmp/hokuto-gocache go test ./...
```

Useful targeted suites:

```sh
go test ./internal/hokuto -run 'Build|Dependency|Parallel'
go test ./internal/hokuto -run 'Install|Manifest|Alternative'
go test ./internal/hokuto -run 'Update|Split|Rebuild'
go test ./internal/hokuto -run 'Fetch|Archive|Checksum'
```

Tests commonly replace global paths with `t.TempDir()`. Restore every modified
global with `t.Cleanup`; do not use `t.Parallel` around shared globals unless
the test fully isolates them. Prefer testing planning/helpers without invoking
real root installs or network access.

Before handing off a change:

1. run `git diff --check`;
2. run the relevant targeted tests and `go test ./...`;
3. inspect `git diff` for unrelated gofmt or user changes;
4. verify sequential and parallel semantics if dependency/build state changed;
5. verify binary and source paths if dependency resolution changed;
6. verify parent and split targets if package identity changed;
7. verify temporary cleanup on both success and failure.

## Common regression patterns

- Calling `pkgBuild` from a top-level workflow and bypassing build orchestration.
- Installing recipe dependencies but forgetting base-devel option policy.
- Treating source recipe dependencies as authoritative for a selected binary.
- Considering a parent package installed when the required split output is not.
- Adding a dependency to a plan without publishing its split output as
  available.
- Updating sequential execution without updating `ParallelManager.canBuild`.
- Dynamically queueing rebuilds without preparing their build dependencies.
- Reusing cached binaries for packages that must rebuild against new libraries
  or headers.
- Losing source/archive/install identity for constrained or cross packages.
- Adding temporary dependencies to `world`, or removing dependencies that
  predated the operation.
- Mutating shared `Config.Values` in parallel code instead of cloning config.
- Printing or prompting under the parallel status line without `WithPrompt`.
- Bypassing staging, manifests, signature verification, or critical-operation
  guards in a new install path.

When uncertain, trace the complete caller chain from `cli.go` to the
orchestration function and only then to the primitive. The correct fix usually
belongs at the orchestration boundary shared by all callers, not as another
partial copy of build or install logic.
