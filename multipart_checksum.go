package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"net/http"
	"strconv"
	"strings"
)

const checksumFull = "FULL_OBJECT"
const checksumComposite = "COMPOSITE"
const checksumTypeHeader = "X-Amz-Checksum-Type"

type multipartChecksum struct {
	Algorithm string
	Type      string
}

var nvmeTable = crc64.MakeTable(0x9a6c9329ac4bc9b5)

func checksumHasher(algorithm string) hash.Hash {
	switch algorithm {
	case "CRC32":
		return crc32.NewIEEE()
	case "CRC32C":
		return crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "CRC64NVME":
		return crc64.New(nvmeTable)
	case "SHA1":
		return sha1.New()
	case "SHA256":
		return sha256.New()
	default:
		return nil
	}
}

func checksumHeader(algorithm string) string {
	return http.CanonicalHeaderKey("X-Amz-Checksum-" + algorithm)
}

func resolveMultipartChecksum(algorithm, kind string) (multipartChecksum, bool) {
	if algorithm == "" && kind == "" {
		return multipartChecksum{}, true
	}
	if checksumHasher(algorithm) == nil {
		return multipartChecksum{}, false
	}
	if kind == "" {
		kind = checksumComposite
		if algorithm == "CRC64NVME" {
			kind = checksumFull
		}
	}
	if kind == checksumFull && strings.HasPrefix(algorithm, "CRC") ||
		kind == checksumComposite && algorithm != "CRC64NVME" {
		return multipartChecksum{algorithm, kind}, true
	}
	return multipartChecksum{}, false
}

type checksumContext struct{}

func computeChecksum(r *http.Request, algorithm string) *http.Request {
	if algorithm == "" {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), checksumContext{}, algorithm))
}

func validatePartChecksumRequest(r *http.Request, upload multipartChecksum) bool {
	if upload.Algorithm == "" {
		return true
	}
	if requested := r.Header.Get("X-Amz-Sdk-Checksum-Algorithm"); requested != "" && requested != upload.Algorithm {
		return false
	}
	if stream, ok := r.Context().Value(streamingTrailerContext{}).(*chunkReader); ok &&
		!strings.EqualFold(stream.trailerName, checksumHeader(upload.Algorithm)) {
		return false
	}
	for name := range r.Header {
		if strings.HasPrefix(name, "X-Amz-Checksum-") && name != checksumHeader(upload.Algorithm) {
			return false
		}
	}
	return true
}

type checksumFields struct {
	ChecksumCRC32     string `xml:",omitempty"`
	ChecksumCRC32C    string `xml:",omitempty"`
	ChecksumCRC64NVME string `xml:",omitempty"`
	ChecksumSHA1      string `xml:",omitempty"`
	ChecksumSHA256    string `xml:",omitempty"`
}

func checksumValues(h http.Header) checksumFields {
	return checksumFields{
		h.Get(checksumHeader("CRC32")), h.Get(checksumHeader("CRC32C")), h.Get(checksumHeader("CRC64NVME")),
		h.Get(checksumHeader("SHA1")), h.Get(checksumHeader("SHA256")),
	}
}

func (f checksumFields) matches(h http.Header) bool {
	got := checksumValues(h)
	return (f.ChecksumCRC32 == "" || f.ChecksumCRC32 == got.ChecksumCRC32) &&
		(f.ChecksumCRC32C == "" || f.ChecksumCRC32C == got.ChecksumCRC32C) &&
		(f.ChecksumCRC64NVME == "" || f.ChecksumCRC64NVME == got.ChecksumCRC64NVME) &&
		(f.ChecksumSHA1 == "" || f.ChecksumSHA1 == got.ChecksumSHA1) &&
		(f.ChecksumSHA256 == "" || f.ChecksumSHA256 == got.ChecksumSHA256)
}

func completeChecksumRequest(r *http.Request, c multipartChecksum) bool {
	for name := range r.Header {
		if !strings.HasPrefix(name, "X-Amz-Checksum-") {
			continue
		}
		if c.Algorithm == "" {
			return false
		}
		if name == checksumTypeHeader {
			if r.Header.Get(name) != c.Type {
				return false
			}
		} else if name != checksumHeader(c.Algorithm) {
			return false
		}
	}
	return true
}

func completedChecksum(h hash.Hash, kind string, parts int) string {
	value := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if kind == checksumComposite {
		value += "-" + strconv.Itoa(parts)
	}
	return value
}
