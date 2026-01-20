package main

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: check_deps <tarball_path>")
		os.Exit(1)
	}

	tarballPath := os.Args[1]
	fmt.Printf("Checking %s...\n", tarballPath)

	f, err := os.Open(tarballPath)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		fmt.Printf("Error creating zstd reader: %v\n", err)
		os.Exit(1)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Error reading tar: %v\n", err)
			os.Exit(1)
		}

		if strings.HasSuffix(hdr.Name, "/depends") {
			fmt.Printf("Found depends file: %s\n", hdr.Name)
			content, _ := io.ReadAll(tr)
			fmt.Printf("Content:\n%s\n", string(content))
			found = true
			break
		}
	}

	if !found {
		fmt.Println("No depends file found!")
		os.Exit(1)
	}
}
