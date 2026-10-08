package hokuto

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// WebsiteRound is one round of hokuto-builder's service in the website's
// rounds.json, which rounds.html lists newest first.
type WebsiteRound struct {
	// Started is when the round began (RFC 3339, UTC); Duration is how long
	// it ran, in seconds.
	Started  string             `json:"started"`
	Duration int64              `json:"duration"`
	Steps    []WebsiteRoundStep `json:"steps"`
	// Cleanup reports the tmpdir cleanup that ends a round.
	Cleanup string `json:"cleanup,omitempty"`
}

// WebsiteRoundStep is one hokuto-builder command of a round.
type WebsiteRoundStep struct {
	Name     string                `json:"name"`
	Status   string                `json:"status"` // "ok" or "failed"
	Exit     int                   `json:"exit,omitempty"`
	Duration int64                 `json:"duration"`
	Packages []WebsiteRoundPackage `json:"packages,omitempty"`
}

// WebsiteRoundPackage is a package build of a step, from HOKUTO_BUILD_RESULTS.
type WebsiteRoundPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Arch      string `json:"arch"`
	Status    string `json:"status"` // "success" or "failed"
	BuildTime int64  `json:"buildtime"`
	Reason    string `json:"reason,omitempty"`
	// Log is the build's log on the site, for the builds packages.html lists.
	Log string `json:"log,omitempty"`
}

// websiteRoundsKept is how many rounds rounds.json keeps.
const websiteRoundsKept = 300

// handleWebsiteRoundCommand publishes the round described by a round file
// (written by hokuto-builder cycle) to the website: hokuto website-round <file>.
func handleWebsiteRoundCommand(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: hokuto website-round <round file>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	round, err := parseWebsiteRound(string(data))
	if err != nil {
		return err
	}
	return publishWebsiteRound(WebsiteRepo, round)
}

// parseWebsiteRound reads a round file, one tab-separated record per line:
//
//	round    <start, Unix seconds>  <duration>
//	step     <name>  <exit status>  <duration>
//	pkg      <a HOKUTO_BUILD_RESULTS line>      (of the step above)
//	cleanup  <text>
func parseWebsiteRound(data string) (WebsiteRound, error) {
	var round WebsiteRound
	seenRound := false
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		switch fields[0] {
		case "round":
			if len(fields) < 3 {
				return round, fmt.Errorf("malformed round line: %q", scanner.Text())
			}
			start, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return round, fmt.Errorf("malformed round start %q", fields[1])
			}
			round.Started = time.Unix(start, 0).UTC().Format(time.RFC3339)
			round.Duration, _ = strconv.ParseInt(fields[2], 10, 64)
			seenRound = true
		case "step":
			if len(fields) < 4 {
				return round, fmt.Errorf("malformed step line: %q", scanner.Text())
			}
			step := WebsiteRoundStep{Name: fields[1], Status: "ok"}
			step.Exit, _ = strconv.Atoi(fields[2])
			if step.Exit != 0 {
				step.Status = "failed"
			}
			step.Duration, _ = strconv.ParseInt(fields[3], 10, 64)
			round.Steps = append(round.Steps, step)
		case "pkg":
			// pkg, time, status, package, version, arch, seconds, reason
			if len(fields) < 7 || len(round.Steps) == 0 {
				return round, fmt.Errorf("malformed pkg line: %q", scanner.Text())
			}
			pkg := WebsiteRoundPackage{Status: fields[2], Name: fields[3], Version: fields[4], Arch: fields[5]}
			pkg.BuildTime, _ = strconv.ParseInt(fields[6], 10, 64)
			if len(fields) > 7 {
				pkg.Reason = fields[7]
			}
			step := &round.Steps[len(round.Steps)-1]
			step.Packages = append(step.Packages, pkg)
		case "cleanup":
			if len(fields) > 1 {
				round.Cleanup = fields[1]
			}
		case "":
		default:
			return round, fmt.Errorf("unknown round record %q", fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return round, err
	}
	if !seenRound {
		return round, fmt.Errorf("no round line in the round file")
	}
	return round, nil
}

// isGenericRoundStep reports whether a step ran in hokuto-builder's generic
// container (hokuto-builder cycle names it "generic rebuild").
func isGenericRoundStep(name string) bool {
	return strings.HasPrefix(name, "generic ")
}

// roundCounts returns how many package builds of the round succeeded and
// failed.
func roundCounts(round WebsiteRound) (built, failed int) {
	for _, step := range round.Steps {
		for _, pkg := range step.Packages {
			if pkg.Status == "success" {
				built++
			} else {
				failed++
			}
		}
	}
	return built, failed
}

// publishWebsiteRound adds round to the front of rounds.json, linking each
// package to the log its build published, then commits and pushes it.
func publishWebsiteRound(websiteRepo string, round WebsiteRound) error {
	if _, err := os.Stat(filepath.Join(websiteRepo, ".git")); err != nil {
		return fmt.Errorf("website repository %s not found", websiteRepo)
	}
	for i := range round.Steps {
		// Generic builds publish no log: one of the same name and version
		// is the optimized build's.
		if isGenericRoundStep(round.Steps[i].Name) {
			continue
		}
		for j := range round.Steps[i].Packages {
			pkg := &round.Steps[i].Packages[j]
			rel := "logs/" + websiteLogName(pkg.Name, pkg.Version, pkg.Arch)
			if _, err := os.Stat(filepath.Join(websiteRepo, rel)); err == nil {
				pkg.Log = rel
			}
		}
	}

	jsonPath := filepath.Join(websiteRepo, "rounds.json")
	var rounds []WebsiteRound
	if data, err := os.ReadFile(jsonPath); err == nil {
		if err := json.Unmarshal(data, &rounds); err != nil {
			colWarn.Printf("Warning: rounds.json is not valid, starting it again: %v\n", err)
			rounds = nil
		}
	}
	rounds = append([]WebsiteRound{round}, rounds...)
	if len(rounds) > websiteRoundsKept {
		rounds = rounds[:websiteRoundsKept]
	}
	data, err := json.MarshalIndent(rounds, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(jsonPath, append(data, '\n'), 0o644); err != nil {
		return err
	}

	if out, err := exec.Command("git", "-C", websiteRepo, "add", "--", "rounds.json").CombinedOutput(); err != nil {
		return fmt.Errorf("git add rounds.json: %v: %s", err, strings.TrimSpace(string(out)))
	}
	built, failed := roundCounts(round)
	started, _ := time.Parse(time.RFC3339, round.Started)
	msg := fmt.Sprintf("Build round %s (%d built, %d failed)", started.Local().Format("2006-01-02 15:04"), built, failed)
	if out, err := exec.Command("git", "-C", websiteRepo, "commit", "-m", msg, "--", "rounds.json").CombinedOutput(); err != nil {
		return fmt.Errorf("git commit rounds.json: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return pushWebsiteRepo(websiteRepo)
}
