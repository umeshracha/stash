package upload

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

const Full = "FULL_OBJECT"
const Composite = "COMPOSITE"
const TypeHeader = "X-Amz-Checksum-Type"

type Checksum struct {
	Algorithm string
	Type      string
}

var nvmeTable = crc64.MakeTable(0x9a6c9329ac4bc9b5)

func Hasher(algorithm string) hash.Hash {
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

func Header(algorithm string) string {
	return http.CanonicalHeaderKey("X-Amz-Checksum-" + algorithm)
}

func Resolve(algorithm, kind string) (Checksum, bool) {
	if algorithm == "" && kind == "" {
		return Checksum{}, true
	}
	if Hasher(algorithm) == nil {
		return Checksum{}, false
	}
	if kind == "" {
		kind = Composite
		if algorithm == "CRC64NVME" {
			kind = Full
		}
	}
	if kind == Full && strings.HasPrefix(algorithm, "CRC") ||
		kind == Composite && algorithm != "CRC64NVME" {
		return Checksum{algorithm, kind}, true
	}
	return Checksum{}, false
}

type checksumContext struct{}

func ComputedAlgorithm(r *http.Request) string {
	algorithm, _ := r.Context().Value(checksumContext{}).(string)
	return algorithm
}

func Compute(r *http.Request, algorithm string) *http.Request {
	if algorithm == "" {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), checksumContext{}, algorithm))
}

func ValidatePart(r *http.Request, upload Checksum) bool {
	if upload.Algorithm == "" {
		return true
	}
	if requested := r.Header.Get("X-Amz-Sdk-Checksum-Algorithm"); requested != "" && requested != upload.Algorithm {
		return false
	}
	if stream, ok := r.Context().Value(streamingTrailerContext{}).(*chunkReader); ok &&
		!strings.EqualFold(stream.trailerName, Header(upload.Algorithm)) {
		return false
	}
	for name := range r.Header {
		if strings.HasPrefix(name, "X-Amz-Checksum-") && name != Header(upload.Algorithm) {
			return false
		}
	}
	return true
}

type Fields struct {
	ChecksumCRC32     string `xml:",omitempty"`
	ChecksumCRC32C    string `xml:",omitempty"`
	ChecksumCRC64NVME string `xml:",omitempty"`
	ChecksumSHA1      string `xml:",omitempty"`
	ChecksumSHA256    string `xml:",omitempty"`
}

func Values(h http.Header) Fields {
	return Fields{
		h.Get(Header("CRC32")), h.Get(Header("CRC32C")), h.Get(Header("CRC64NVME")),
		h.Get(Header("SHA1")), h.Get(Header("SHA256")),
	}
}

func (f Fields) Matches(h http.Header) bool {
	got := Values(h)
	return (f.ChecksumCRC32 == "" || f.ChecksumCRC32 == got.ChecksumCRC32) &&
		(f.ChecksumCRC32C == "" || f.ChecksumCRC32C == got.ChecksumCRC32C) &&
		(f.ChecksumCRC64NVME == "" || f.ChecksumCRC64NVME == got.ChecksumCRC64NVME) &&
		(f.ChecksumSHA1 == "" || f.ChecksumSHA1 == got.ChecksumSHA1) &&
		(f.ChecksumSHA256 == "" || f.ChecksumSHA256 == got.ChecksumSHA256)
}

func ValidateCompletion(r *http.Request, c Checksum) bool {
	for name := range r.Header {
		if !strings.HasPrefix(name, "X-Amz-Checksum-") {
			continue
		}
		if c.Algorithm == "" {
			return false
		}
		if name == TypeHeader {
			if r.Header.Get(name) != c.Type {
				return false
			}
		} else if name != Header(c.Algorithm) {
			return false
		}
	}
	return true
}

func Completed(h hash.Hash, kind string, parts int) string {
	value := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if kind == Composite {
		value += "-" + strconv.Itoa(parts)
	}
	return value
}
