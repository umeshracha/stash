package server

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"stash/internal/sigv4"
)

func TestSignedStreamRejectsTampering(t *testing.T) {
	const date = "20260101T000000Z"
	const scope = "20260101/us-east-1/s3/aws4_request"
	key := []byte("test signing key")
	seed := strings.Repeat("0", 64)
	sign := func(previous, payload string) string {
		message := strings.Join([]string{
			"AWS4-HMAC-SHA256-PAYLOAD", date, scope, previous, digest(""), digest(payload),
		}, "\n")
		return hex.EncodeToString(sigv4.MAC(key, message))
	}
	part := sign(seed, "hello")
	final := sign(part, "")
	for _, tc := range []struct {
		name, data string
		valid      bool
	}{
		{"valid", fmt.Sprintf("5;chunk-signature=%s\r\nhello\r\n0;chunk-signature=%s\r\n\r\n", part, final), true},
		{"changed data", fmt.Sprintf("5;chunk-signature=%s\r\nHELLO\r\n0;chunk-signature=%s\r\n\r\n", part, final), false},
		{"missing final chunk", fmt.Sprintf("5;chunk-signature=%s\r\nhello\r\n", part), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &chunkReader{
				body:       bufio.NewReader(strings.NewReader(tc.data)),
				signingKey: key, scope: scope, date: date, previous: seed,
				expected: 5, hash: sha256.New(),
			}
			body, err := io.ReadAll(reader)
			if tc.valid {
				if err != nil || string(body) != "hello" {
					t.Fatalf("unexpected stream: %q, %v", body, err)
				}
			} else if !errors.Is(err, errChecksum) {
				t.Fatalf("expected checksum error, got %v", err)
			}
		})
	}
}

func TestStreamingChecksumTrailer(t *testing.T) {
	const name = "x-amz-checksum-crc32"
	const value = "NhCmhg=="
	const date = "20260101T000000Z"
	const scope = "20260101/us-east-1/s3/aws4_request"
	key := []byte("test signing key")
	seed := strings.Repeat("0", 64)
	sign := func(previous, payload string) string {
		message := strings.Join([]string{
			"AWS4-HMAC-SHA256-PAYLOAD", date, scope, previous, digest(""), digest(payload),
		}, "\n")
		return hex.EncodeToString(sigv4.MAC(key, message))
	}
	part := sign(seed, "hello")
	final := sign(part, "")
	checksum := name + ":" + value
	trailerSignature := hex.EncodeToString(sigv4.MAC(key, strings.Join([]string{
		"AWS4-HMAC-SHA256-TRAILER", date, scope, final, digest(checksum + "\n"),
	}, "\n")))
	unsigned := "5\r\nhello\r\n0\r\n" + checksum + "\r\n\r\n"
	signed := fmt.Sprintf("5;chunk-signature=%s\r\nhello\r\n0;chunk-signature=%s\r\n%s\r\nx-amz-trailer-signature:%s\r\n\r\n", part, final, checksum, trailerSignature)
	for _, tc := range []struct {
		name, data    string
		signed, valid bool
	}{
		{"unsigned", unsigned, false, true},
		{"signed", signed, true, true},
		{"alternate line ending", strings.Replace(unsigned, checksum+"\r\n", checksum+"\n\r\n", 1), false, true},
		{"wrong checksum", strings.Replace(unsigned, value, "AAAAAAAA", 1), false, false},
		{"wrong checksum field", strings.Replace(unsigned, name, name+"c", 1), false, false},
		{"tampered signature", strings.Replace(signed, trailerSignature, seed, 1), true, false},
		{"duplicate checksum", strings.Replace(unsigned, checksum, checksum+"\r\n"+checksum, 1), false, false},
		{"trailing bytes", signed + "extra", true, false},
		{"missing trailer", "5\r\nhello\r\n0\r\n\r\n", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &chunkReader{
				body: bufio.NewReader(strings.NewReader(tc.data)), expected: 5,
				trailerName: name, checksum: checksumHasher("CRC32"),
			}
			if tc.signed {
				reader.signingKey, reader.scope, reader.date, reader.previous = key, scope, date, seed
				reader.hash = sha256.New()
			}
			body, err := io.ReadAll(reader)
			if tc.valid {
				if err != nil || string(body) != "hello" || reader.trailerValue != value {
					t.Fatalf("unexpected stream: %q, %q, %v", body, reader.trailerValue, err)
				}
			} else if !errors.Is(err, errChecksum) {
				t.Fatalf("expected checksum error, got %v", err)
			}
		})
	}
}
