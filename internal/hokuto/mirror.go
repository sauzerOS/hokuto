package hokuto

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gookit/color"
)

// Mirror represents a mirror configuration
type Mirror struct {
	Name      string
	URL       string
	Type      string // "http", "s3", "r2"
	Region    string
	AccessKey string
	SecretKey string
	Bucket    string
	PublicURL string // For downloads if different from endpoint
}

// getMirrorDisplayName returns a human-readable name for the active mirror
func getMirrorDisplayName(cfg *Config) string {
	name := cfg.Values["HOKUTO_MIRROR_NAME"]
	if name == "" {
		if cfg.Values["R2_ACCESS_KEY_ID"] != "" {
			return "R2"
		}
		return "Remote Mirror"
	}
	// Prettify common default name
	if name == "cloudflare-r2" {
		return "R2"
	}
	return name
}

func loadMirrors(cfg *Config) []Mirror {
	var mirrors []Mirror
	seen := make(map[string]bool)

	// Check for MIRROR_LIST
	listStr := cfg.Values["MIRROR_LIST"]
	if listStr != "" {
		names := strings.Split(listStr, ",")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			m := Mirror{
				Name:      name,
				URL:       cfg.Values["MIRROR_"+name+"_URL"],
				Type:      cfg.Values["MIRROR_"+name+"_TYPE"],
				Region:    cfg.Values["MIRROR_"+name+"_REGION"],
				AccessKey: cfg.Values["MIRROR_"+name+"_ACCESS_KEY"],
				SecretKey: cfg.Values["MIRROR_"+name+"_SECRET_KEY"],
				Bucket:    cfg.Values["MIRROR_"+name+"_BUCKET"],
				PublicURL: cfg.Values["MIRROR_"+name+"_PUBLIC_URL"],
			}
			if m.URL != "" {
				mirrors = append(mirrors, m)
				seen[name] = true
			}
		}
	}

	// Also check individual checks if list missed or not used
	for k, v := range cfg.Values {
		if strings.HasPrefix(k, "MIRROR_") && strings.HasSuffix(k, "_URL") {
			name := strings.TrimSuffix(strings.TrimPrefix(k, "MIRROR_"), "_URL")
			if seen[name] {
				continue
			}
			// Only valid if name doesn't contain underscores? e.g. MIRROR_NAME_URL
			// Let's assume name is the part between MIRROR_ and _URL
			m := Mirror{
				Name:      name,
				URL:       v,
				Type:      cfg.Values["MIRROR_"+name+"_TYPE"],
				Region:    cfg.Values["MIRROR_"+name+"_REGION"],
				AccessKey: cfg.Values["MIRROR_"+name+"_ACCESS_KEY"],
				SecretKey: cfg.Values["MIRROR_"+name+"_SECRET_KEY"],
				Bucket:    cfg.Values["MIRROR_"+name+"_BUCKET"],
				PublicURL: cfg.Values["MIRROR_"+name+"_PUBLIC_URL"],
			}
			mirrors = append(mirrors, m)
			seen[name] = true
		}
	}

	// Sort by name
	sort.Slice(mirrors, func(i, j int) bool {
		return mirrors[i].Name < mirrors[j].Name
	})

	// Synthetic entry for default Cloudflare R2 if configured via legacy vars
	if cfg.Values["R2_ACCOUNT_ID"] != "" && !seen["cloudflare-r2"] {
		r2Mirror := Mirror{
			Name:      "cloudflare-r2",
			URL:       fmt.Sprintf("https://%s.r2.cloudflarestorage.com/sauzeros", cfg.Values["R2_ACCOUNT_ID"]),
			Type:      "r2",
			Bucket:    cfg.Values["R2_BUCKET_NAME"],
			AccessKey: cfg.Values["R2_ACCESS_KEY_ID"],
			SecretKey: cfg.Values["R2_SECRET_ACCESS_KEY"],
		}
		if r2Mirror.Bucket == "" {
			r2Mirror.Bucket = "sauzeros"
		}
		// Prepend or append? Append is fine, user can switch to it.
		mirrors = append(mirrors, r2Mirror)
	}

	return mirrors
}

// HandleMirrorCommand manages mirror configuration
func HandleMirrorCommand(args []string, cfg *Config) error {
	if len(args) == 0 {
		return listMirrors(cfg)
	}

	cmd := args[0]
	switch cmd {
	case "list", "ls":
		return listMirrors(cfg)
	case "use", "set":
		if len(args) < 2 {
			return fmt.Errorf("usage: hokuto mirror use <name>")
		}
		return setMirror(cfg, args[1])
	case "add":
		// add <name> <url> [type]
		if len(args) < 3 {
			return fmt.Errorf("usage: hokuto mirror add <name> <url> [type]")
		}
		mType := "http"
		if len(args) > 3 {
			mType = args[3]
		}
		return addMirror(cfg, args[1], args[2], mType)
	default:
		return fmt.Errorf("unknown mirror command: %s", cmd)
	}
}

func listMirrors(cfg *Config) error {
	mirrors := loadMirrors(cfg)
	activeMirror := cfg.Values["HOKUTO_MIRROR"]
	activeName := cfg.Values["HOKUTO_MIRROR_NAME"]

	colSuccess.Println("Configured Mirrors:")
	if len(mirrors) == 0 {
		fmt.Println("  (No mirrors configured)")
	}

	for _, m := range mirrors {
		isActive := false
		if activeName == m.Name || activeMirror == m.URL {
			isActive = true
		}

		prefix := "  "
		if isActive {
			prefix = "* "
			color.Success.Printf("%s%s (%s)\n", prefix, m.Name, m.Type)
		} else {
			fmt.Printf("%s%s (%s)\n", prefix, m.Name, m.Type)
		}
		fmt.Printf("    URL: %s\n", m.URL)
		if m.PublicURL != "" {
			fmt.Printf("    Public: %s\n", m.PublicURL)
		}
	}

	if activeName == "" && activeMirror != "" {
		fmt.Println("\nActive Manual Mirror URL:")
		fmt.Printf("* %s\n", activeMirror)
	}

	return nil
}

func setMirror(cfg *Config, name string) error {
	mirrors := loadMirrors(cfg)
	var found *Mirror
	for _, m := range mirrors {
		if m.Name == name {
			found = &m
			break
		}
	}

	if found == nil {
		return fmt.Errorf("mirror '%s' not found", name)
	}

	// Update config via setConfigValue
	// We only set HOKUTO_MIRROR_NAME for authenticated operations (uploads)
	if err := setConfigValue(cfg, "HOKUTO_MIRROR_NAME", found.Name); err != nil {
		return err
	}

	// Also set specific S3 env vars if needed?
	// The fetcher needs to know credentials if using private S3.
	// But current fetcher is HTTP based.

	colSuccess.Printf("Switched to mirror: %s\n", name)
	return nil
}

func addMirror(cfg *Config, name, url, mType string) error {
	// Add to config file
	if err := setConfigValue(cfg, "MIRROR_"+name+"_URL", url); err != nil {
		return err
	}
	if err := setConfigValue(cfg, "MIRROR_"+name+"_TYPE", mType); err != nil {
		return err
	}

	// Update MIRROR_LIST
	listStr := cfg.Values["MIRROR_LIST"]
	names := []string{}
	if listStr != "" {
		names = strings.Split(listStr, ",")
	}

	exists := false
	for _, n := range names {
		if strings.TrimSpace(n) == name {
			exists = true
			break
		}
	}

	if !exists {
		names = append(names, name)
		newList := strings.Join(names, ",")
		if err := setConfigValue(cfg, "MIRROR_LIST", newList); err != nil {
			return err
		}
	}

	colSuccess.Printf("Added mirror: %s\n", name)
	return nil
}
