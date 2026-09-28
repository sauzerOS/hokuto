package hokuto

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// loadUpdateOrderChains reads /etc/hokuto/hokuto.update. Each non-comment
// line is a chain: its packages must be processed left to right.
func loadUpdateOrderChains() [][]string {
	data, err := os.ReadFile(filepath.Join(rootDir, "etc", "hokuto", "hokuto.update"))
	if err != nil {
		return nil
	}
	var chains [][]string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if fields := strings.Fields(line); len(fields) > 1 {
			chains = append(chains, fields)
		}
	}
	return chains
}

// orderByUpdateChains returns names reordered so that every chain is
// respected, while keeping the input order wherever no chain says otherwise.
//
// alias maps a package named in a chain to the entry of names that stands for
// it (a pkgset member to the set being bumped); names map to themselves.
// Within a chain only the entries present in names count, so in "a b c" with
// b absent, a still comes before c.
//
// It is a stable topological sort: at each step the earliest remaining name
// (in input order) whose predecessors are all placed goes next. Chains that
// contradict each other cannot all be honoured; whatever is left then follows
// in input order.
func orderByUpdateChains(names []string, chains [][]string, alias map[string]string) []string {
	position := make(map[string]int, len(names))
	for i, name := range names {
		position[name] = i
	}
	resolve := func(pkg string) (string, bool) {
		if target, ok := alias[pkg]; ok {
			pkg = target
		}
		_, ok := position[pkg]
		return pkg, ok
	}

	successors := make(map[string]map[string]bool)
	indegree := make(map[string]int, len(names))
	for _, chain := range chains {
		prev := ""
		for _, pkg := range chain {
			name, ok := resolve(pkg)
			if !ok || name == prev {
				continue
			}
			if prev != "" {
				if successors[prev] == nil {
					successors[prev] = make(map[string]bool)
				}
				if !successors[prev][name] {
					successors[prev][name] = true
					indegree[name]++
				}
			}
			prev = name
		}
	}
	if len(successors) == 0 {
		return names
	}

	ordered := make([]string, 0, len(names))
	placed := make([]bool, len(names))
	for len(ordered) < len(names) {
		next := -1
		for i, name := range names {
			if !placed[i] && indegree[name] == 0 {
				next = i
				break
			}
		}
		if next == -1 {
			// Contradictory chains: keep the rest in input order.
			for i, name := range names {
				if !placed[i] {
					ordered = append(ordered, name)
				}
			}
			break
		}
		placed[next] = true
		ordered = append(ordered, names[next])
		for succ := range successors[names[next]] {
			indegree[succ]--
		}
	}
	return ordered
}

// orderAutoBumpCandidates applies the hokuto.update chains to the auto-bump
// candidates. A pkgset candidate takes part through its members, so a chain
// naming one of them orders the whole set.
func orderAutoBumpCandidates(candidates []AutoBumpCandidate, sets map[string][]string, chains [][]string) []AutoBumpCandidate {
	if len(chains) == 0 || len(candidates) < 2 {
		return candidates
	}
	names := make([]string, len(candidates))
	byName := make(map[string]AutoBumpCandidate, len(candidates))
	alias := make(map[string]string)
	for i, cand := range candidates {
		names[i] = cand.PkgName
		byName[cand.PkgName] = cand
	}
	for _, cand := range candidates {
		if !cand.IsPkgSet {
			continue
		}
		for _, member := range sets[cand.PkgName] {
			// A member bumped on its own keeps its own place.
			if _, isCandidate := byName[member]; !isCandidate {
				alias[member] = cand.PkgName
			}
		}
	}
	ordered := make([]AutoBumpCandidate, 0, len(candidates))
	for _, name := range orderByUpdateChains(names, chains, alias) {
		ordered = append(ordered, byName[name])
	}
	return ordered
}

// updatePlanRecipeDir locates the recipe that builds pkg, following split
// outputs back to their source recipe.
func updatePlanRecipeDir(pkg string) (string, bool) {
	if dir, err := findPackageDir(pkg); err == nil {
		return dir, true
	}
	if _, dir, ok := findSplitPackageSource(pkg); ok {
		return dir, true
	}
	return "", false
}

// recipeDependencyNames returns every package a recipe's depends files
// mention, whatever the flags and including all alternatives. Using more names
// than the resolver did only adds ordering constraints, which is the safe
// direction here. ok is false when the files cannot be parsed.
func recipeDependencyNames(dir string) (map[string]bool, bool) {
	names := make(map[string]bool)
	files, _ := filepath.Glob(filepath.Join(dir, "depends*"))
	splitFiles, _ := filepath.Glob(filepath.Join(dir, "split", "*", "depends"))
	for _, file := range append(files, splitFiles...) {
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, false
		}
		deps, err := parseDependsData(content)
		if err != nil {
			return nil, false
		}
		for _, dep := range deps {
			names[dep.Name] = true
			for _, alt := range dep.Alternatives {
				names[alt] = true
			}
		}
	}
	return names, true
}

// orderUpdatePlan applies the hokuto.update chains to a dependency-ordered
// update list without ever building a package before one of its
// dependencies.
//
// The input is the resolver's order, so it already respects dependencies.
// Those constraints go into the graph first: an edge wherever a package
// depends on one listed earlier. A package whose dependencies cannot be read
// is pinned in place relative to everything else. Chain edges are added last,
// each only if it does not close a cycle, so a chain that contradicts a
// dependency is dropped rather than honoured. The result is a stable
// topological sort over the input order.
func orderUpdatePlan(names []string, chains [][]string) []string {
	if len(chains) == 0 || len(names) < 2 {
		return names
	}
	position := make(map[string]int, len(names))
	for i, name := range names {
		position[name] = i
	}

	successors := make(map[string]map[string]bool)
	indegree := make(map[string]int, len(names))
	addEdge := func(from, to string) {
		if successors[from] == nil {
			successors[from] = make(map[string]bool)
		}
		if !successors[from][to] {
			successors[from][to] = true
			indegree[to]++
		}
	}

	// Dependencies may name a split output of a listed recipe.
	recipeDirs := make(map[string]string, len(names))
	providedBy := make(map[string]string)
	for _, name := range names {
		dir, ok := updatePlanRecipeDir(name)
		if !ok {
			continue
		}
		recipeDirs[name] = dir
		for _, split := range splitPackageNamesFromDir(dir) {
			if _, listed := position[split]; !listed {
				providedBy[split] = name
			}
		}
	}

	for i, name := range names {
		var deps map[string]bool
		dir, ok := recipeDirs[name]
		if ok {
			deps, ok = recipeDependencyNames(dir)
		}
		if !ok {
			for j, other := range names {
				switch {
				case j < i:
					addEdge(other, name)
				case j > i:
					addEdge(name, other)
				}
			}
			continue
		}
		for dep := range deps {
			target := dep
			if _, listed := position[target]; !listed {
				target = providedBy[dep]
			}
			// Only dependencies the resolver placed earlier; a later one is
			// a cycle it already broke, and its order stays as it is.
			if p, listed := position[target]; listed && target != name && p < i {
				addEdge(target, name)
			}
		}
	}

	reaches := func(from, to string) bool {
		seen := map[string]bool{from: true}
		stack := []string{from}
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if cur == to {
				return true
			}
			for next := range successors[cur] {
				if !seen[next] {
					seen[next] = true
					stack = append(stack, next)
				}
			}
		}
		return false
	}
	for _, chain := range chains {
		prev := ""
		for _, pkg := range chain {
			if _, listed := position[pkg]; !listed {
				continue
			}
			if prev != "" && !reaches(pkg, prev) {
				addEdge(prev, pkg)
			} else if prev != "" {
				debugf("hokuto.update: keeping %s before %s, a dependency requires it\n", pkg, prev)
			}
			prev = pkg
		}
	}

	ordered := make([]string, 0, len(names))
	placed := make([]bool, len(names))
	for len(ordered) < len(names) {
		next := -1
		for i, name := range names {
			if !placed[i] && indegree[name] == 0 {
				next = i
				break
			}
		}
		if next == -1 {
			// Unreachable: every edge is checked for cycles. Fall back to the
			// resolver's order rather than risk a wrong one.
			return names
		}
		placed[next] = true
		ordered = append(ordered, names[next])
		for succ := range successors[names[next]] {
			indegree[succ]--
		}
	}
	return ordered
}
