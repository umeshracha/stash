package fsutil

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func syncObjectFiles(requests []*directoryRequest) {
	if len(requests) > 1 && sameLocalAPFS(requests) {
		var flush *directoryRequest
		for _, request := range requests {
			for {
				request.err = unix.Fsync(int(request.file.Fd()))
				if !errors.Is(request.err, unix.EINTR) {
					break
				}
			}
			if request.err == nil {
				flush = request
			}
		}
		// fsync submits every file's writes. Full sync flushes the drive's
		// cache once for the batch, before any file is renamed.
		if flush != nil {
			for {
				_, err := unix.FcntlInt(flush.file.Fd(), unix.F_FULLFSYNC, 0)
				if err == nil {
					return
				}
				if !errors.Is(err, unix.EINTR) {
					break
				}
			}
		}
	}
	for _, request := range requests {
		if request.err == nil {
			request.err = request.file.Sync()
		}
	}
}

func canBatchObjectFile(file *os.File) bool {
	var stat unix.Statfs_t
	return unix.Fstatfs(int(file.Fd()), &stat) == nil &&
		stat.Flags&unix.MNT_LOCAL != 0 && unix.ByteSliceToString(stat.Fstypename[:]) == "apfs"
}

func sameLocalAPFS(requests []*directoryRequest) bool {
	var first unix.Statfs_t
	if err := unix.Fstatfs(int(requests[0].file.Fd()), &first); err != nil ||
		first.Flags&unix.MNT_LOCAL == 0 || unix.ByteSliceToString(first.Fstypename[:]) != "apfs" {
		return false
	}
	for _, request := range requests[1:] {
		var current unix.Statfs_t
		if err := unix.Fstatfs(int(request.file.Fd()), &current); err != nil || current.Fsid != first.Fsid {
			return false
		}
	}
	return true
}
