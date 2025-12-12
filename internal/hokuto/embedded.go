package hokuto

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// listEmbeddedImages returns the list of image asset names (relative to assets/)
func listEmbeddedImages() ([]string, error) {
	entries, err := embeddedImages.ReadDir("assets")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// displayEmbeddedWithChafa writes the embedded image to a secure temp file and runs chafa.
// ctx: use a cancellable context (pass the main ctx so Ctrl+C cancels chafa)
// imgRelPath: the name relative to "assets/" (e.g., "foo.png")
// chafaArgs: additional chafa flags (optional)
func displayEmbeddedWithChafa(ctx context.Context, imgRelPath string, chafaArgs ...string) error {
	// Read embedded bytes
	data, err := embeddedImages.ReadFile(filepath.Join("assets", imgRelPath))
	if err != nil {
		return fmt.Errorf("embedded image not found: %w", err)
	}

	// Create secure temp file
	f, err := os.CreateTemp("", "hokuto-img-*.png")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()

	// Ensure file removed; keep f open long enough to write+sync
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write temp image: %w", err)
	}
	_ = f.Sync() // best-effort
	if err := f.Close(); err != nil {
		return fmt.Errorf("close tmp image: %w", err)
	}

	// Build chafa args: [tmpPath] + chafaArgs...
	args := append([]string{tmpPath}, chafaArgs...)
	cmd := exec.CommandContext(ctx, "chafa", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Run and return any error (context cancels command when ctx done)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("chafa failed: %w", err)
	}
	return nil
}
