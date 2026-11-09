package server

import (
	"io"
	"net/http"
	"os"
	"stash/internal/encryption"
)

func setEncryptionHeader(w http.ResponseWriter, obj object) {
	if obj.Encryption != nil {
		w.Header().Set("X-Amz-Server-Side-Encryption", "AES256")
	}
}

func (obj object) payloadSize() int64 {
	return encryption.PayloadSize(obj.Size, obj.Encryption)
}

func (s *store) stagingWriter(file *os.File, key string) (io.Writer, func() (*encryption.Metadata, error), error) {
	return s.encryption.Writer(file, key)
}
