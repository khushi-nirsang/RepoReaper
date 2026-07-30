//go:build !windows

package report

import "os"

func replaceReportFile(source, target string) error {
	return os.Rename(source, target)
}
