//go:build !windows

package scanner

import "os"

func replaceCacheFile(source, target string) error {
	return os.Rename(source, target)
}
