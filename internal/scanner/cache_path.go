package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// validateBlobCachePath confines cache files to a dedicated root and rejects
// every existing parent component that can redirect traversal. Missing
// components are safe for the caller to create and are checked again after
// creation.
func validateBlobCachePath(root, candidate string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("%w: resolve root: %v", errCachePath, err)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return fmt.Errorf("%w: resolve path: %v", errCachePath, err)
	}
	if !pathWithinDirectory(root, candidate) {
		return errCachePath
	}

	parent := filepath.Dir(candidate)
	relative, err := filepath.Rel(root, parent)
	if err != nil || filepath.IsAbs(relative) {
		return errCachePath
	}
	current := root
	components := []string{}
	if relative != "." {
		components = splitCachePath(relative)
	}
	components = append([]string{""}, components...)
	for _, component := range components {
		if component != "" {
			current = filepath.Join(current, component)
		}
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			// Descendants cannot exist without this parent. MkdirAll will
			// create ordinary directories, followed by a second validation.
			return nil
		}
		if statErr != nil {
			return fmt.Errorf("%w: inspect parent: %v", errCachePath, statErr)
		}
		if cachePathComponentUnsafe(info) || !info.IsDir() {
			return errCachePath
		}
	}
	return nil
}

func splitCachePath(relative string) []string {
	var components []string
	for relative != "." && relative != "" {
		directory, base := filepath.Split(relative)
		if base != "" {
			components = append([]string{base}, components...)
		}
		relative = filepath.Clean(directory)
	}
	return components
}
