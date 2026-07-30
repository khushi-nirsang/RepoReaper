//go:build !windows

package scanner

import "os"

func cachePathComponentUnsafe(info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}
