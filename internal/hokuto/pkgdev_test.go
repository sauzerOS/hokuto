package hokuto

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRepologyURLForRepositoryReplacesInRepo(t *testing.T) {
	got, err := repologyURLForRepository(
		"https://repology.example/api/v1/projects/?inrepo=sauzeros&outdated=1",
		"sauzeros-cosmic",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "inrepo=sauzeros-cosmic") {
		t.Fatalf("repository was not replaced in %q", got)
	}
	if !strings.Contains(got, "outdated=1") {
		t.Fatalf("unrelated query parameter was not preserved in %q", got)
	}
}

func TestOptionalAutoBumpRepositoriesPromptAndRunInRequestedOrder(t *testing.T) {
	var prompted []string
	var ran []string
	err := runOptionalAutoBumpRepositories(
		false,
		func(string) bool { return true },
		func(repository autoBumpRepository) bool {
			prompted = append(prompted, repository.DisplayName)
			return repository.DisplayName == "Cosmic"
		},
		func(repository autoBumpRepository) error {
			ran = append(ran, repository.DisplayName)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Cosmic", "KDE"}; !reflect.DeepEqual(prompted, want) {
		t.Fatalf("unexpected prompt order: got %v want %v", prompted, want)
	}
	if want := []string{"Cosmic"}; !reflect.DeepEqual(ran, want) {
		t.Fatalf("unexpected processed repositories: got %v want %v", ran, want)
	}
}

func TestOptionalAutoBumpRepositoriesSkipUnavailableAndHonorAssumeYes(t *testing.T) {
	var prompted bool
	var ran []string
	err := runOptionalAutoBumpRepositories(
		true,
		func(path string) bool { return path == "/repo/kde" },
		func(autoBumpRepository) bool {
			prompted = true
			return false
		},
		func(repository autoBumpRepository) error {
			ran = append(ran, repository.DisplayName)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if prompted {
		t.Fatal("--yes should not prompt for optional repositories")
	}
	if want := []string{"KDE"}; !reflect.DeepEqual(ran, want) {
		t.Fatalf("unexpected processed repositories: got %v want %v", ran, want)
	}
}

func TestOptionalAutoBumpRepositoryErrorIncludesRepository(t *testing.T) {
	err := runOptionalAutoBumpRepositories(
		true,
		func(path string) bool { return path == "/repo/cosmic" },
		func(autoBumpRepository) bool { return true },
		func(autoBumpRepository) error { return errors.New("feed unavailable") },
	)
	if err == nil || !strings.Contains(err.Error(), "Cosmic repository auto-bump failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrioritizeAutoBumpRepository(t *testing.T) {
	current := strings.Join([]string{"/repo/sauzeros/core", "/repo/cosmic", "/repo/sauzeros/extra"}, string(os.PathListSeparator))
	got := filepath.SplitList(prioritizeAutoBumpRepository("/repo/cosmic", current))
	want := []string{"/repo/cosmic", "/repo/sauzeros/core", "/repo/sauzeros/extra"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected repository order: got %v want %v", got, want)
	}
}
