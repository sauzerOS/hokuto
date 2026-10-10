package hokuto

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// The no-build list names recipes the build server leaves alone. A native
// entry is still bumped by "bump --build" but not built, and "update
// --build-missing-binaries" (hokuto-builder rebuild) skips it; a cross entry
// is skipped by cross-sync and cross-sync -system. Unlike the build
// blacklist, which a failed build fills and a new release empties, entries
// stay until they are removed: hokuto nobuild remove.

type noBuildEntry struct {
	Package string `json:"package"`
	// Cross marks an entry for the aarch64 builds of cross-sync; the native
	// builds of bump and rebuild ignore it, and the other way round.
	Cross   bool      `json:"cross,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

func noBuildKey(pkgName string, cross bool) string {
	if cross {
		return pkgName + "@cross"
	}
	return pkgName
}

func loadNoBuildList() (map[string]noBuildEntry, error) {
	entries := make(map[string]noBuildEntry)
	data, err := os.ReadFile(NoBuildFile)
	if err != nil {
		if os.IsNotExist(err) {
			return entries, nil
		}
		return nil, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return entries, nil
	}
	var list []noBuildEntry
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("%s: %w", NoBuildFile, err)
	}
	for _, e := range list {
		if e.Package != "" {
			entries[noBuildKey(e.Package, e.Cross)] = e
		}
	}
	return entries, nil
}

func saveNoBuildList(entries map[string]noBuildEntry) error {
	list := make([]noBuildEntry, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Package != list[j].Package {
			return list[i].Package < list[j].Package
		}
		return !list[i].Cross && list[j].Cross
	})
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return writeStateFile(NoBuildFile, append(data, '\n'))
}

// noBuildListed reports whether pkgName (a recipe, or a cross-system
// package such as aarch64-gcc, which counts as its recipe) is on the
// no-build list for the native or, with cross, the cross builds.
func noBuildListed(entries map[string]noBuildEntry, pkgName string, cross bool) bool {
	if _, ok := entries[noBuildKey(pkgName, cross)]; ok {
		return true
	}
	if base := strings.TrimPrefix(pkgName, crossSyncPrefix); base != pkgName {
		_, ok := entries[noBuildKey(base, cross)]
		return ok
	}
	return false
}

// filterNoBuild drops from pkgs those on the no-build list for the given
// builds and reports them. A list that cannot be read keeps every package.
func filterNoBuild(pkgs []string, cross bool) []string {
	pkgs = filterHeldPython(pkgs)
	entries, err := loadNoBuildList()
	if err != nil {
		colWarn.Printf("Warning: failed to read the no-build list: %v\n", err)
		return pkgs
	}
	if len(entries) == 0 {
		return pkgs
	}
	kept := pkgs[:0:0]
	var skipped []string
	for _, pkgName := range pkgs {
		if noBuildListed(entries, pkgName, cross) {
			skipped = append(skipped, pkgName)
			continue
		}
		kept = append(kept, pkgName)
	}
	if len(skipped) > 0 {
		colArrow.Print("-> ")
		colNote.Printf("Not built, on the no-build list (hokuto nobuild): %s\n", strings.Join(skipped, ", "))
	}
	return kept
}

// noBuildHelp is what hokuto nobuild --help prints.
const noBuildHelp = `Usage: hokuto nobuild [command] [-cross | -native] [package...]

The no-build list: packages the build server never builds until they are
removed from it. Native entries are bumped by bump --build but not built,
and skipped by update --build-missing-binaries (hokuto-builder rebuild);
-cross entries are skipped by cross-sync and cross-sync -system.

Commands:
  list                    show the list (the default without packages)
  add <package>...        add packages (the default with packages)
  remove <package>...     remove packages
  clear                   empty the list

Options:
  -cross                  cross-build entries: add them, or limit list,
                          remove and clear to them
  -native                 limit list, remove and clear to native entries
  -h, --help              show this help
`

// wantsCommandHelp reports whether a command's arguments ask for its help.
func wantsCommandHelp(args []string) bool {
	for _, arg := range args {
		switch arg {
		case "-h", "-help", "--help", "help":
			return true
		}
	}
	return false
}

// handleNoBuildCommand lists or edits the no-build list:
//
//	hokuto nobuild [list]
//	hokuto nobuild [add] [-cross] <pkg>...
//	hokuto nobuild remove [-cross|-native] <pkg>...
//	hokuto nobuild clear [-cross|-native]
func handleNoBuildCommand(args []string) error {
	if wantsCommandHelp(args) {
		fmt.Print(noBuildHelp)
		return nil
	}
	cmd := ""
	scope := "" // "", "cross" or "native"
	var pkgs []string
	for _, arg := range args {
		switch arg {
		case "-cross", "--cross":
			scope = "cross"
		case "-native", "--native":
			scope = "native"
		default:
			if strings.HasPrefix(arg, "-") {
				return fmt.Errorf("unknown option %q", arg)
			}
			if cmd == "" && len(pkgs) == 0 {
				switch arg {
				case "list", "ls", "add", "remove", "rm", "del", "clear":
					cmd = arg
					continue
				}
			}
			pkgs = append(pkgs, arg)
		}
	}
	if cmd == "" {
		cmd = "list"
		if len(pkgs) > 0 {
			cmd = "add"
		}
	}

	entries, err := loadNoBuildList()
	if err != nil {
		return err
	}
	switch cmd {
	case "list", "ls":
		if len(entries) == 0 {
			colArrow.Print("-> ")
			colSuccess.Println("The no-build list is empty.")
			return nil
		}
		keys := make([]string, 0, len(entries))
		for k := range entries {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			e := entries[k]
			if (scope == "cross" && !e.Cross) || (scope == "native" && e.Cross) {
				continue
			}
			where := "native"
			if e.Cross {
				where = "cross"
			}
			fmt.Printf("%-32s %-8s since %s\n", e.Package, where, e.AddedAt.Local().Format("2006-01-02 15:04"))
		}
		return nil
	case "add":
		if len(pkgs) == 0 {
			return fmt.Errorf("usage: hokuto nobuild [add] [-cross] <pkg>...")
		}
		if scope == "native" {
			scope = ""
		}
		var added []string
		for _, pkgName := range pkgs {
			if _, err := findPackageMetadataDir(strings.TrimPrefix(pkgName, crossSyncPrefix)); err != nil {
				colWarn.Printf("Warning: %s has no recipe; adding it anyway\n", pkgName)
			}
			key := noBuildKey(pkgName, scope == "cross")
			if _, ok := entries[key]; ok {
				continue
			}
			entries[key] = noBuildEntry{Package: pkgName, Cross: scope == "cross", AddedAt: time.Now()}
			added = append(added, pkgName)
		}
		if len(added) == 0 {
			colArrow.Print("-> ")
			colNote.Println("Already on the no-build list.")
			return nil
		}
		if err := saveNoBuildList(entries); err != nil {
			return err
		}
		where := "native builds (bump, rebuild)"
		if scope == "cross" {
			where = "cross builds (cross-sync, cross-sync -system)"
		}
		colArrow.Print("-> ")
		colSuccess.Printf("Added to the no-build list for %s: %s\n", where, strings.Join(added, ", "))
		return nil
	case "remove", "rm", "del":
		if len(pkgs) == 0 {
			return fmt.Errorf("usage: hokuto nobuild remove [-cross|-native] <pkg>...")
		}
		removed := removeNoBuildEntries(entries, pkgs, scope)
		if len(removed) == 0 {
			colArrow.Print("-> ")
			colNote.Println("None of them is on the no-build list.")
			return nil
		}
		if err := saveNoBuildList(entries); err != nil {
			return err
		}
		colArrow.Print("-> ")
		colSuccess.Printf("Removed from the no-build list: %s\n", strings.Join(removed, ", "))
		return nil
	case "clear":
		if len(pkgs) > 0 {
			return fmt.Errorf("usage: hokuto nobuild clear [-cross|-native]")
		}
		var all []string
		for _, e := range entries {
			all = append(all, e.Package)
		}
		removed := removeNoBuildEntries(entries, all, scope)
		if len(removed) == 0 {
			return nil
		}
		if err := saveNoBuildList(entries); err != nil {
			return err
		}
		colArrow.Print("-> ")
		colSuccess.Printf("Cleared %d no-build entries.\n", len(removed))
		return nil
	}
	return fmt.Errorf("unknown nobuild command %q (list, add, remove, clear)", cmd)
}

// removeNoBuildEntries removes pkgs' entries for one scope ("cross" or
// "native") or, with scope "", both; it returns what it removed.
func removeNoBuildEntries(entries map[string]noBuildEntry, pkgs []string, scope string) []string {
	want := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		want[p] = true
	}
	var removed []string
	for key, e := range entries {
		if !want[e.Package] {
			continue
		}
		if (scope == "cross" && !e.Cross) || (scope == "native" && e.Cross) {
			continue
		}
		delete(entries, key)
		label := e.Package
		if e.Cross {
			label += " (cross)"
		}
		removed = append(removed, label)
	}
	sort.Strings(removed)
	return removed
}

// filterHeldPython drops python from pkgs while its upgrade is held.
func filterHeldPython(pkgs []string) []string {
	kept := pkgs[:0:0]
	for _, pkgName := range pkgs {
		if pythonUpgradeHeld(pkgName) {
			colArrow.Print("-> ")
			colNote.Printf("Not built: %s\n", heldPythonNote())
			continue
		}
		kept = append(kept, pkgName)
	}
	return kept
}
