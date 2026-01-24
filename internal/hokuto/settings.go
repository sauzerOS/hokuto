package hokuto

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gookit/color"
)

// handleSettingsCommand provides an interactive menu to adjust hokuto settings
func handleSettingsCommand(cfg *Config) error {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println()
		colArrow.Print("-> ")
		colSuccess.Println("Hokuto Settings")
		fmt.Println("--------------------------------")

		// 1. LTO
		ltoStatus := "Disabled"
		if cfg.DefaultLTO {
			ltoStatus = "Enabled"
		}
		fmt.Printf("1) Toggle LTO: [%s]\n", color.Note.Sprint(ltoStatus))

		// 2. Generic/Native
		buildType := "Native"
		if HokutoGeneric {
			buildType = "Generic"
		}
		fmt.Printf("2) Toggle Build Type: [%s]\n", color.Note.Sprint(buildType))

		// 3. Signature Check
		sigStatus := "Disabled"
		if VerifySignature {
			sigStatus = "Enabled"
		}
		fmt.Printf("3) Toggle Signature Check: [%s]\n", color.Note.Sprint(sigStatus))

		// 4. GNU Mirror
		fmt.Printf("4) Select GNU Mirror: [%s]\n", color.Note.Sprint(gnuMirrorURL))

		// 5. Debug Mode
		debugStatus := "Disabled"
		if Debug {
			debugStatus = "Enabled"
		}
		fmt.Printf("5) Toggle Debug Mode: [%s]\n", color.Note.Sprint(debugStatus))

		// 6. Active Signing Key
		fmt.Printf("6) Set Active Signing Key: [%s]\n", color.Note.Sprint(activeKeyID))

		// 7. Generate New Key Pair
		fmt.Println("7) Generate New Key Pair")

		fmt.Println("q) Quit")
		fmt.Println("--------------------------------")
		fmt.Print("Choice: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if choice == "q" {
			break
		}

		switch choice {
		case "1":
			newValue := "0"
			if !cfg.DefaultLTO {
				newValue = "1"
			}
			if err := setConfigValue(cfg, "HOKUTO_LTO", newValue); err != nil {
				colError.Printf("Error: %v\n", err)
			} else {
				colSuccess.Println("LTO updated successfully.")
			}

		case "2":
			newValue := "0"
			if !HokutoGeneric {
				newValue = "1"
			}
			if err := setConfigValue(cfg, "HOKUTO_GENERIC", newValue); err != nil {
				colError.Printf("Error: %v\n", err)
			} else {
				colSuccess.Println("Build type updated successfully.")
			}

		case "3":
			newValue := "0"
			if !VerifySignature {
				newValue = "1"
			}
			if err := setConfigValue(cfg, "HOKUTO_VERIFY_SIGNATURE", newValue); err != nil {
				colError.Printf("Error: %v\n", err)
			} else {
				colSuccess.Println("Signature check updated successfully.")
			}

		case "4":
			fmt.Println("\nAvailable GNU Mirrors:")
			fmt.Println("1) TH: https://mirror.cyberbits.asia/gnu/")
			fmt.Println("2) EU: https://mirror.cyberbits.eu/gnu/")
			fmt.Println("3) US: https://mirrors.ocf.berkeley.edu/gnu/")
			fmt.Println("4) Default: https://mirrors.kernel.org/gnu")
			fmt.Print("Choice: ")

			mChoice, _ := reader.ReadString('\n')
			mChoice = strings.TrimSpace(mChoice)
			var newMirror string
			switch mChoice {
			case "1":
				newMirror = "https://mirror.cyberbits.asia/gnu/"
			case "2":
				newMirror = "https://mirror.cyberbits.eu/gnu/"
			case "3":
				newMirror = "https://mirrors.ocf.berkeley.edu/gnu/"
			case "4":
				newMirror = "https://mirrors.kernel.org/gnu"
			}

			if newMirror != "" {
				if err := setConfigValue(cfg, "GNU_MIRROR", newMirror); err != nil {
					colError.Printf("Error: %v\n", err)
				} else {
					colSuccess.Println("GNU Mirror updated successfully.")
				}
			}

		case "5":
			newValue := "0"
			if !Debug {
				newValue = "1"
			}
			if err := setConfigValue(cfg, "HOKUTO_DEBUG", newValue); err != nil {
				colError.Printf("Error: %v\n", err)
			} else {
				colSuccess.Println("Debug mode updated successfully.")
			}

		case "6":
			// Set Active Signing Key
			keyDir := "/etc/hokuto/keys"
			if root := os.Getenv("HOKUTO_ROOT"); root != "" {
				keyDir = filepath.Join(root, "etc", "hokuto", "keys")
			}

			files, _ := filepath.Glob(filepath.Join(keyDir, "*.key"))
			if len(files) == 0 {
				colWarn.Println("No signing keys found in", keyDir)
				continue
			}

			fmt.Println("\nAvailable Signing Keys:")
			keys := make([]string, 0)
			for i, f := range files {
				id := strings.TrimSuffix(filepath.Base(f), ".key")
				// Translate hokuto.key back to "official" for the ID
				if id == "hokuto" {
					id = officialKeyID
				}
				keys = append(keys, id)
				fmt.Printf("%d) %s\n", i+1, id)
			}
			fmt.Print("Choice: ")

			kChoice, _ := reader.ReadString('\n')
			kChoice = strings.TrimSpace(kChoice)
			var selectedID string
			for i, id := range keys {
				if kChoice == fmt.Sprintf("%d", i+1) {
					selectedID = id
					break
				}
			}

			if selectedID != "" {
				if err := setConfigValue(cfg, "HOKUTO_KEY_ID", selectedID); err != nil {
					colError.Printf("Error: %v\n", err)
				} else {
					colSuccess.Printf("Active signing key set to: %s\n", selectedID)
				}
			}

		case "7":
			// Generate New Key Pair
			fmt.Print("\nEnter Key ID for new pair (e.g. community): ")
			keyID, _ := reader.ReadString('\n')
			keyID = strings.TrimSpace(keyID)
			if keyID == "" {
				colWarn.Println("Invalid Key ID.")
				continue
			}

			keyDir := "/etc/hokuto/keys"
			if root := os.Getenv("HOKUTO_ROOT"); root != "" {
				keyDir = filepath.Join(root, "etc", "hokuto", "keys")
			}
			privPath := filepath.Join(keyDir, keyID+".key")
			if _, err := os.Stat(privPath); err == nil {
				colError.Printf("Error: Key '%s' already exists.\n", keyID)
				continue
			}

			colArrow.Print("-> ")
			fmt.Printf("Generating Ed25519 key pair for '%s'...\n", keyID)
			if err := GenerateKeyPair(keyID, RootExec); err != nil {
				colError.Printf("Error: %v\n", err)
			} else {
				colSuccess.Printf("Key pair for '%s' generated successfully.\n", keyID)
				colNote.Printf("Private key: %s\n", privPath)
				colNote.Printf("Public key: %s/keys/%s.pub\n", filepath.Dir(keyDir), keyID)
			}

		default:
			colWarn.Println("Invalid choice.")
		}
	}

	return nil
}
