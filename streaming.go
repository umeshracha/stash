package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const signedStream = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"

const signedTrailerStream = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
const unsignedTrailerStream = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"

type streamingTrailerContext struct{}

type chunkReader struct {
	trailerValue string
	trailerName  string
	checksum     hash.Hash
	body         *bufio.Reader
	signingKey   []byte
	scope        string
	date         string
	previous     string
	signature    []byte
	hash         hash.Hash
	remaining    int64
	expected     int64
	complete     bool
}

// unwrapStreamingUpload runs only after authorization verifies the request signature.
func unwrapStreamingUpload(r *http.Request, c credential, region string, mode string) error {
	length, err := strconv.ParseInt(r.Header.Get("X-Amz-Decoded-Content-Length"), 10, 64)
	if err != nil || length < 0 {
		return errChecksum
	}
	if length > maxObject {
		return errTooLarge
	}
	reader := &chunkReader{body: bufio.NewReaderSize(r.Body, 4096), expected: length}
	if mode != signedStream {
		name := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Amz-Trailer")))
		suffix, ok := strings.CutPrefix(name, "x-amz-checksum-")
		algorithm := strings.ToUpper(suffix)
		reader.checksum = checksumHasher(algorithm)
		requested := r.Header.Get("X-Amz-Sdk-Checksum-Algorithm")
		if !ok || reader.checksum == nil || len(r.Header.Values("X-Amz-Trailer")) != 1 ||
			len(r.Header.Values(name)) != 0 || requested != "" && requested != algorithm {
			return errChecksum
		}
		reader.trailerName = name
		*r = *r.WithContext(context.WithValue(r.Context(), streamingTrailerContext{}, reader))
	}
	if mode != unsignedTrailerStream {
		date := r.Header.Get("X-Amz-Date")
		if len(date) < 8 {
			return errChecksum
		}
		for _, field := range strings.Split(r.Header.Get("Authorization"), ",") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(field), "Signature="); ok {
				reader.previous = strings.ToLower(value)
			}
		}
		if len(reader.previous) != 64 {
			return errChecksum
		}
		reader.date = date
		reader.scope = date[:8] + "/" + region + "/s3/aws4_request"
		reader.signingKey = mac([]byte("AWS4"+c.Secret), date[:8])
		for _, value := range []string{region, "s3", "aws4_request"} {
			reader.signingKey = mac(reader.signingKey, value)
		}
		reader.hash = sha256.New()
	}
	r.Body = struct {
		io.Reader
		io.Closer
	}{reader, r.Body}
	r.ContentLength = length
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	var encodings []string
	for _, encoding := range strings.Split(r.Header.Get("Content-Encoding"), ",") {
		encoding = strings.TrimSpace(encoding)
		if encoding != "" && !strings.EqualFold(encoding, "aws-chunked") {
			encodings = append(encodings, encoding)
		}
	}
	r.Header.Del("Content-Encoding")
	if len(encodings) != 0 {
		r.Header.Set("Content-Encoding", strings.Join(encodings, ", "))
	}
	return nil
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.complete {
		return 0, io.EOF
	}
	if r.remaining == 0 {
		line, ok := r.readLine()
		if !ok {
			return 0, errChecksum
		}
		sizeText, signature, found := strings.Cut(line, ";chunk-signature=")
		if found != (r.signingKey != nil) || found && len(signature) != 64 {
			return 0, errChecksum
		}
		size, err := strconv.ParseUint(sizeText, 16, 63)
		if err != nil || int64(size) > r.expected {
			return 0, errChecksum
		}
		if found {
			r.signature, err = hex.DecodeString(signature)
			if err != nil {
				return 0, errChecksum
			}
			r.hash.Reset()
		}
		r.remaining = int64(size)
		r.expected -= r.remaining
		if size == 0 {
			if r.expected != 0 || !r.verifyChunk() || !r.finishStream() {
				return 0, errChecksum
			}
			r.complete = true
			return 0, io.EOF
		}
	}
	n, err := io.ReadFull(r.body, p[:min(int64(len(p)), r.remaining)])
	if r.hash != nil {
		r.hash.Write(p[:n])
	}
	if r.checksum != nil {
		r.checksum.Write(p[:n])
	}
	r.remaining -= int64(n)
	if err != nil || r.remaining == 0 && (!r.readSeparator() || !r.verifyChunk()) {
		return n, errChecksum
	}
	return n, nil
}

func (r *chunkReader) readLine() (string, bool) {
	line, err := r.body.ReadSlice('\n')
	return strings.TrimSuffix(string(line), "\r\n"), err == nil && strings.HasSuffix(string(line), "\r\n")
}

func (r *chunkReader) readSeparator() bool {
	var separator [2]byte
	_, err := io.ReadFull(r.body, separator[:])
	return err == nil && separator == [2]byte{'\r', '\n'}
}

func (r *chunkReader) verifyChunk() bool {
	if r.signingKey == nil {
		return true
	}
	message := strings.Join([]string{"AWS4-HMAC-SHA256-PAYLOAD", r.date, r.scope,
		r.previous, digest(""), hex.EncodeToString(r.hash.Sum(nil))}, "\n")
	if !hmac.Equal(r.signature, mac(r.signingKey, message)) {
		return false
	}
	r.previous = hex.EncodeToString(r.signature)
	return true
}

func (r *chunkReader) finishStream() bool {
	if r.checksum == nil {
		if !r.readSeparator() {
			return false
		}
	} else if !r.readTrailer() {
		return false
	}
	_, err := r.body.ReadByte()
	return err == io.EOF
}

func (r *chunkReader) readTrailer() bool {
	line, err := r.body.ReadSlice('\n')
	if err != nil {
		return false
	}
	field := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
	name, value, _ := strings.Cut(field, ":")
	if !strings.EqualFold(name, r.trailerName) || value != base64.StdEncoding.EncodeToString(r.checksum.Sum(nil)) {
		return false
	}
	if !strings.HasSuffix(string(line), "\r\n") && !r.readSeparator() {
		return false
	}
	if r.signingKey != nil {
		line, ok := r.readLine()
		signature, found := strings.CutPrefix(line, "x-amz-trailer-signature:")
		if !ok || !found || len(signature) != 64 {
			return false
		}
		raw, err := hex.DecodeString(signature)
		message := strings.Join([]string{"AWS4-HMAC-SHA256-TRAILER", r.date, r.scope,
			r.previous, digest(r.trailerName + ":" + value + "\n")}, "\n")
		if err != nil || !hmac.Equal(raw, mac(r.signingKey, message)) {
			return false
		}
	}
	if !r.readSeparator() {
		return false
	}
	r.trailerValue = value
	return true
}
