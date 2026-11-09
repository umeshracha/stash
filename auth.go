package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type credential struct {
	Secret  string            `json:"secret"`
	Buckets map[string]string `json:"buckets"`
}

func digest(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func mac(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(value))
	return h.Sum(nil)
}

func encode(s string, keepSlash bool) string {
	const digits = "0123456789ABCDEF"
	var out strings.Builder
	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			strings.ContainsRune("-_.~", rune(c)) || keepSlash && c == '/' {
			out.WriteByte(c)
		} else {
			out.WriteByte('%')
			out.WriteByte(digits[c>>4])
			out.WriteByte(digits[c&15])
		}
	}
	return out.String()
}

func (s *server) authorize(r *http.Request) (credential, bool) {
	const algorithm = "AWS4-HMAC-SHA256"
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), algorithm+" ")
	if !ok {
		return credential{}, false
	}
	fields := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found || fields[key] != "" {
			return credential{}, false
		}
		fields[key] = value
	}
	scope := strings.Split(fields["Credential"], "/")
	if len(scope) != 5 || scope[2] != s.region || scope[3] != "s3" || scope[4] != "aws4_request" {
		return credential{}, false
	}
	c, ok := s.credentials[scope[0]]
	if !ok {
		return credential{}, false
	}
	date := r.Header.Get("X-Amz-Date")
	at, err := time.Parse("20060102T150405Z", date)
	if err != nil || at.Format("20060102") != scope[1] || time.Since(at).Abs() > 15*time.Minute {
		return credential{}, false
	}

	signed := strings.Split(fields["SignedHeaders"], ";")
	if !sort.StringsAreSorted(signed) {
		return credential{}, false
	}
	var headers strings.Builder
	hasHost, hasDate := false, false
	for i, name := range signed {
		if name == "" || name != strings.ToLower(name) || i > 0 && signed[i-1] == name {
			return credential{}, false
		}
		values := r.Header.Values(name)
		switch name {
		case "host":
			hasHost = true
			values = []string{r.Host}
		case "content-length":
			if r.ContentLength < 0 {
				return credential{}, false
			}
			values = []string{strconv.FormatInt(r.ContentLength, 10)}
		case "x-amz-date":
			hasDate = true
		}
		if len(values) == 0 {
			return credential{}, false
		}
		for j := range values {
			// Avoid modifying the request's header values.
			if j == 0 {
				headers.WriteString(name + ":")
			} else {
				headers.WriteByte(',')
			}
			headers.WriteString(strings.Join(strings.Fields(values[j]), " "))
		}
		headers.WriteByte('\n')
	}
	if !hasHost || !hasDate {
		return credential{}, false
	}
	for name := range r.Header {
		name = strings.ToLower(name)
		if strings.HasPrefix(name, "x-amz-") && name != "x-amz-content-sha256" {
			index := sort.SearchStrings(signed, name)
			if index == len(signed) || signed[index] != name {
				return credential{}, false
			}
		}
	}
	var query []string
	parsed, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return credential{}, false
	}
	for name, values := range parsed {
		for _, value := range values {
			query = append(query, encode(name, false)+"="+encode(value, false))
		}
	}
	sort.Slice(query, func(i, j int) bool {
		left, _, _ := strings.Cut(query[i], "=")
		right, _, _ := strings.Cut(query[j], "=")
		if left == right {
			return query[i] < query[j]
		}
		return left < right
	})
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload == "" {
		return credential{}, false
	}
	canonical := strings.Join([]string{r.Method, encode(r.URL.Path, true),
		strings.Join(query, "&"), headers.String(), fields["SignedHeaders"], payload}, "\n")
	signingScope := strings.Join(scope[1:], "/")
	message := strings.Join([]string{algorithm, date, signingScope, digest(canonical)}, "\n")
	key := mac([]byte("AWS4"+c.Secret), scope[1])
	for _, part := range scope[2:] {
		key = mac(key, part)
	}
	signature, err := hex.DecodeString(fields["Signature"])
	return c, err == nil && hmac.Equal(signature, mac(key, message))
}
