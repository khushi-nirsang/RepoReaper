//go:build windows

package report

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var moveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func replaceReportFile(source, target string) error {
	sourcePointer, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPointer, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	result, _, callErr := moveFileExW.Call(
		uintptr(unsafe.Pointer(sourcePointer)),
		uintptr(unsafe.Pointer(targetPointer)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if result == 0 {
		// MoveFileEx can reject replacement on some Windows filesystem
		// configurations (notably when the destination inherits restrictive
		// sharing flags). Fall back to the ordinary same-volume rename after
		// removing only the explicitly requested destination.
		if removeErr := os.Remove(target); removeErr == nil {
			if renameErr := os.Rename(source, target); renameErr == nil {
				return nil
			}
		}
		return fmt.Errorf("atomically replace report: %w", callErr)
	}
	return nil
}
