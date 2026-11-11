package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// Error is an authentication failure. It carries the status and S3 error code a
// client expects, so an SDK can tell a wrong secret from a wrong region or a slow clock.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

var (
	// ErrAnonymous means the request carried no credentials at all.
	ErrAnonymous = &Error{403, "AccessDenied", "Access Denied"}
	// ErrInvalidAccessKey means the access key ID is not configured.
	ErrInvalidAccessKey = &Error{403, "InvalidAccessKeyId", "The access key ID you provided does not exist in our records."}
	// ErrSignature means the signature does not match what the server computed.
	ErrSignature = &Error{403, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided. Check your secret access key and signing method."}
	// ErrClockSkew means the request time is too far from the server's clock. SDKs
	// correct their clock from the Date header of this response and retry.
	ErrClockSkew = &Error{403, "RequestTimeTooSkewed", "The difference between the request time and the current time is too large."}
	// ErrExpired means a presigned URL is past its expiry.
	ErrExpired = &Error{403, "AccessDenied", "Request has expired"}
	// ErrNoPayloadHash means a signed request omitted x-amz-content-sha256.
	ErrNoPayloadHash = &Error{400, "InvalidRequest", "Missing required header for this request: x-amz-content-sha256"}
)

// now is the clock; tests replace it.
var now = time.Now

// Verify authenticates an S3 request and returns the verified access key ID. A
// failure is always an *Error.
func Verify(r *http.Request, region string, lookupSecret func(string) (string, bool)) (string, error) {
	const algorithm = "AWS4-HMAC-SHA256"
	parsed, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", &Error{400, "AuthorizationQueryParametersError", "the query string cannot be parsed"}
	}
	presigned := parsed.Has("X-Amz-Algorithm")
	if !presigned && r.Header.Get("Authorization") == "" {
		return "", ErrAnonymous
	}
	// Malformed input is a 400 naming the part that is wrong, not an access denial.
	malformed := func(format string, args ...any) *Error {
		code := "AuthorizationHeaderMalformed"
		if presigned {
			code = "AuthorizationQueryParametersError"
		}
		return &Error{400, code, fmt.Sprintf(format, args...)}
	}
	fields := map[string]string{}
	date := r.Header.Get("X-Amz-Date")
	expiry := 15 * time.Minute
	if presigned {
		if r.Header.Get("Authorization") != "" || parsed.Get("X-Amz-Algorithm") != algorithm {
			return "", malformed("query authentication supports only %s, and not together with an Authorization header", algorithm)
		}
		for _, name := range presignParams {
			if len(parsed[name]) != 1 {
				return "", malformed("%s must be given exactly once", name)
			}
		}
		seconds, err := strconv.Atoi(parsed.Get("X-Amz-Expires"))
		if err != nil || seconds < 1 || seconds > 604800 {
			return "", malformed("X-Amz-Expires must be a number of seconds from 1 to 604800")
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
			return "", malformed("the Authorization header must start with %s", algorithm)
		}
		for _, part := range strings.Split(raw, ",") {
			key, value, found := strings.Cut(strings.TrimSpace(part), "=")
			if !found || fields[key] != "" {
				return "", malformed("the Authorization header must list Credential, SignedHeaders and Signature once each as name=value")
			}
			fields[key] = value
		}
	}
	scope := strings.Split(fields["Credential"], "/")
	if len(scope) != 5 {
		return "", malformed("the credential must be <access key ID>/<date>/<region>/s3/aws4_request")
	}
	if scope[2] != region {
		return "", malformed("the region '%s' is wrong; expecting '%s'", scope[2], region)
	}
	if scope[3] != "s3" || scope[4] != "aws4_request" {
		return "", malformed("the credential scope must end in s3/aws4_request")
	}
	secret, ok := lookupSecret(scope[0])
	if !ok {
		return "", ErrInvalidAccessKey
	}
	at, err := time.Parse("20060102T150405Z", date)
	if err != nil || at.Format("20060102") != scope[1] {
		return "", malformed("the request date must be in YYYYMMDDTHHMMSSZ form and on the credential's date")
	}
	if now().Sub(at) > expiry {
		if presigned {
			return "", ErrExpired
		}
		return "", ErrClockSkew
	}
	if at.Sub(now()) > 15*time.Minute {
		return "", ErrClockSkew
	}

	signed := strings.Split(fields["SignedHeaders"], ";")
	if !sort.StringsAreSorted(signed) {
		return "", malformed("SignedHeaders must be sorted")
	}
	var headers strings.Builder
	hasHost, hasDate := false, false
	for i, name := range signed {
		if name == "" || name != strings.ToLower(name) || i > 0 && signed[i-1] == name {
			return "", malformed("SignedHeaders must list each header once, in lower case")
		}
		values := r.Header.Values(name)
		switch name {
		case "host":
			hasHost = true
			values = []string{r.Host}
		case "content-length":
			if r.ContentLength < 0 {
				return "", ErrSignature
			}
			values = []string{strconv.FormatInt(r.ContentLength, 10)}
		case "x-amz-date":
			hasDate = true
		}
		if len(values) == 0 {
			return "", ErrSignature
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
		return "", malformed("SignedHeaders must include host, and x-amz-date unless the URL is presigned")
	}
	for name := range r.Header {
		name = strings.ToLower(name)
		if strings.HasPrefix(name, "x-amz-") && (presigned || name != "x-amz-content-sha256") {
			index := sort.SearchStrings(signed, name)
			if index == len(signed) || signed[index] != name {
				return "", &Error{403, "AccessDenied", "There were headers present in the request which were not signed: " + name}
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
		return "", ErrNoPayloadHash
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
		return "", ErrSignature
	}
	return scope[0], nil
}

// RemovePresignParams leaves only application query parameters.
func RemovePresignParams(query url.Values) {
	for _, name := range presignParams {
		query.Del(name)
	}
}
