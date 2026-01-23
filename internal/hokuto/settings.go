package hokuto

import (
	"bufio"
	"fmt"
	"os"
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

		default:
			colWarn.Println("Invalid choice.")
		}
	}

	return nil
}
