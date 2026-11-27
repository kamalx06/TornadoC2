//go:build linux

package update

import "os"

func replaceFile(src, dst string) error {
	return os.Rename(src, dst)
}
