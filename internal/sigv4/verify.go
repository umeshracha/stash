package sigv4

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

var presignParams = []string{"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature"}

func digest(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// MAC computes the HMAC-SHA256 used for request and chunk signatures.
func MAC(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(value))
	return h.Sum(nil)
}

// Encode applies SigV4 percent-encoding, optionally preserving path separators.
func Encode(s string, keepSlash bool) string {
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

// Verify authenticates an S3 request and returns the verified access key ID.
func Verify(r *http.Request, region string, lookupSecret func(string) (string, bool)) (string, bool) {
	const algorithm = "AWS4-HMAC-SHA256"
	parsed, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", false
	}
	presigned := parsed.Has("X-Amz-Algorithm")
	fields := map[string]string{}
	date := r.Header.Get("X-Amz-Date")
	expiry := 15 * time.Minute
	if presigned {
		if r.Header.Get("Authorization") != "" || parsed.Get("X-Amz-Algorithm") != algorithm {
			return "", false
		}
		for _, name := range presignParams {
			if len(parsed[name]) != 1 {
				return "", false
			}
		}
		seconds, err := strconv.Atoi(parsed.Get("X-Amz-Expires"))
		if err != nil || seconds < 1 || seconds > 604800 {
			return "", false
		}
		expiry = time.Duration(seconds) * time.Second
		date = parsed.Get("X-Amz-Date")
		for _, name := range []string{"Credential", "SignedHeaders", "Signature"} {
			fields[name] = parsed.Get("X-Amz-" + name)
		}
		parsed.Del("X-Amz-Signature")
	} else {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), algorithm+" ")
		if !ok {
			return "", false
		}
		for _, part := range strings.Split(raw, ",") {
			key, value, found := strings.Cut(strings.TrimSpace(part), "=")
			if !found || fields[key] != "" {
				return "", false
			}
			fields[key] = value
		}
	}
	scope := strings.Split(fields["Credential"], "/")
	if len(scope) != 5 || scope[2] != region || scope[3] != "s3" || scope[4] != "aws4_request" {
		return "", false
	}
	secret, ok := lookupSecret(scope[0])
	if !ok {
		return "", false
	}
	at, err := time.Parse("20060102T150405Z", date)
	if err != nil || at.Format("20060102") != scope[1] || time.Since(at) > expiry || time.Until(at) > 15*time.Minute {
		return "", false
	}

	signed := strings.Split(fields["SignedHeaders"], ";")
	if !sort.StringsAreSorted(signed) {
		return "", false
	}
	var headers strings.Builder
	hasHost, hasDate := false, false
	for i, name := range signed {
		if name == "" || name != strings.ToLower(name) || i > 0 && signed[i-1] == name {
			return "", false
		}
		values := r.Header.Values(name)
		switch name {
		case "host":
			hasHost = true
			values = []string{r.Host}
		case "content-length":
			if r.ContentLength < 0 {
				return "", false
			}
			values = []string{strconv.FormatInt(r.ContentLength, 10)}
		case "x-amz-date":
			hasDate = true
		}
		if len(values) == 0 {
			return "", false
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
	if !hasHost || !presigned && !hasDate {
		return "", false
	}
	for name := range r.Header {
		name = strings.ToLower(name)
		if strings.HasPrefix(name, "x-amz-") && (presigned || name != "x-amz-content-sha256") {
			index := sort.SearchStrings(signed, name)
			if index == len(signed) || signed[index] != name {
				return "", false
			}
		}
	}
	var query []string
	for name, values := range parsed {
		for _, value := range values {
			query = append(query, Encode(name, false)+"="+Encode(value, false))
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
	if presigned {
		payload = "UNSIGNED-PAYLOAD"
	}
	if payload == "" {
		return "", false
	}
	canonical := strings.Join([]string{r.Method, Encode(r.URL.Path, true),
		strings.Join(query, "&"), headers.String(), fields["SignedHeaders"], payload}, "\n")
	signingScope := strings.Join(scope[1:], "/")
	message := strings.Join([]string{algorithm, date, signingScope, digest(canonical)}, "\n")
	key := MAC([]byte("AWS4"+secret), scope[1])
	for _, part := range scope[2:] {
		key = MAC(key, part)
	}
	signature, err := hex.DecodeString(fields["Signature"])
	if err != nil || !hmac.Equal(signature, MAC(key, message)) {
		return "", false
	}
	return scope[0], true
}

// RemovePresignParams leaves only application query parameters.
func RemovePresignParams(query url.Values) {
	for _, name := range presignParams {
		query.Del(name)
	}
}
