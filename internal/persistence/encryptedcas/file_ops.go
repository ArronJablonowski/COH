package encryptedcas

import (
	"io"
	"os"
)

// fileOperations is adapter-private so fault tests can force exact durability
// boundaries without exposing paths, generic callbacks, or filesystem access
// through the workflow contract.
type fileOperations struct {
	create        func(string) (*os.File, error)
	writer        func(*os.File) io.Writer
	sync          func(*os.File) error
	stat          func(*os.File) (os.FileInfo, error)
	close         func(*os.File) error
	openRegular   func(string) (*os.File, os.FileInfo, error)
	link          func(string, string) error
	remove        func(string) error
	syncDirectory func(string) error
}

func defaultFileOperations() fileOperations {
	return fileOperations{
		create: func(path string) (*os.File, error) {
			return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		},
		writer:      func(file *os.File) io.Writer { return file },
		sync:        func(file *os.File) error { return file.Sync() },
		stat:        func(file *os.File) (os.FileInfo, error) { return file.Stat() },
		close:       func(file *os.File) error { return file.Close() },
		openRegular: realOpenRegular, link: os.Link, remove: os.Remove,
		syncDirectory: realSyncDirectory,
	}
}
