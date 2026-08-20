//go:build windows

package filesize

import (
	"fmt"
	"os"
)

func fileIdentity(info os.FileInfo) (string, error) {
	return fmt.Sprintf("windows:%d:%d", info.Size(), info.ModTime().UnixNano()), nil
}
