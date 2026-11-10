//go:build !darwin

package fsutil

import "os"

func canBatchObjectFile(_ *os.File) bool { return false }

func syncObjectFiles(requests []*directoryRequest) {
	for _, request := range requests {
		request.err = request.file.Sync()
	}
}
