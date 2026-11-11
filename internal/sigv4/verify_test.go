package sigv4

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The two requests below are the worked examples in the AWS Signature Version 4
// documentation for S3 (GET Object with a Range header, and the same object
// presigned), so they pin the canonical request and signing steps against AWS's
// own published signatures rather than against this code.
const (
	exampleKey    = "AKIAIOSFODNN7EXAMPLE"
	exampleSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	emptyPayload  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	exampleSig    = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	presignedSig  = "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
)

var exampleTime = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

func lookup(id string) (string, bool) { return exampleSecret, id == exampleKey }

func at(t *testing.T, moment time.Time) {
	t.Helper()
	previous := now
	now = func() time.Time { return moment }
	t.Cleanup(func() { now = previous })
}

func headerRequest() *http.Request {
	r, _ := http.NewRequest("GET", "http://examplebucket.s3.amazonaws.com/test.txt", nil)
	r.Header.Set("Range", "bytes=0-9")
	r.Header.Set("X-Amz-Content-Sha256", emptyPayload)
	r.Header.Set("X-Amz-Date", "20130524T000000Z")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+exampleKey+"/20130524/us-east-1/s3/aws4_request,"+
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature="+exampleSig)
	return r
}

func presignedRequest() *http.Request {
	r, _ := http.NewRequest("GET", "http://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256"+
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z"+
		"&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature="+presignedSig, nil)
	return r
}

func TestVerifyAcceptsTheAWSDocumentationExamples(t *testing.T) {
	at(t, exampleTime.Add(time.Minute))
	for name, r := range map[string]*http.Request{"header": headerRequest(), "presigned": presignedRequest()} {
		id, err := Verify(r, "us-east-1", lookup)
		if err != nil || id != exampleKey {
			t.Errorf("%s: got %q, %v; want the documented request to verify", name, id, err)
		}
	}
}

func TestVerifyNamesTheReasonItRefuses(t *testing.T) {
	tests := []struct {
		name    string
		request func() *http.Request
		clock   time.Time
		code    string
		status  int
		message string
	}{
		{"no credentials", func() *http.Request {
			r := headerRequest()
			r.Header.Del("Authorization")
			return r
		}, exampleTime, "AccessDenied", 403, ""},
		{"unknown access key", func() *http.Request {
			r := headerRequest()
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), exampleKey, "AKIANOTCONFIGURED", 1))
			return r
		}, exampleTime, "InvalidAccessKeyId", 403, ""},
		{"wrong secret or tampered request", func() *http.Request {
			r := headerRequest()
			r.URL.Path = "/other.txt"
			return r
		}, exampleTime, "SignatureDoesNotMatch", 403, ""},
		{"wrong region", func() *http.Request {
			r := headerRequest()
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "us-east-1", "eu-west-1", 1))
			return r
		}, exampleTime, "AuthorizationHeaderMalformed", 400, "the region 'eu-west-1' is wrong; expecting 'us-east-1'"},
		{"clock too far ahead of the request", headerRequest, exampleTime.Add(time.Hour), "RequestTimeTooSkewed", 403, ""},
		{"clock too far behind the request", headerRequest, exampleTime.Add(-time.Hour), "RequestTimeTooSkewed", 403, ""},
		{"header the signature does not cover", func() *http.Request {
			r := headerRequest()
			r.Header.Set("X-Amz-Meta-Owner", "someone")
			return r
		}, exampleTime, "AccessDenied", 403, "not signed: x-amz-meta-owner"},
		{"signed headers out of order", func() *http.Request {
			r := headerRequest()
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "host;range", "range;host", 1))
			return r
		}, exampleTime, "AuthorizationHeaderMalformed", 400, "SignedHeaders must be sorted"},
		{"missing payload hash", func() *http.Request {
			r := headerRequest()
			r.Header.Del("X-Amz-Content-Sha256")
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), ";x-amz-content-sha256", "", 1))
			return r
		}, exampleTime, "InvalidRequest", 400, "x-amz-content-sha256"},
		{"presigned URL past its expiry", presignedRequest, exampleTime.Add(25 * time.Hour), "AccessDenied", 403, "Request has expired"},
		{"presigned URL with a bad expiry", func() *http.Request {
			r := presignedRequest()
			r.URL.RawQuery = strings.Replace(r.URL.RawQuery, "X-Amz-Expires=86400", "X-Amz-Expires=0", 1)
			return r
		}, exampleTime, "AuthorizationQueryParametersError", 400, "X-Amz-Expires"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			at(t, tc.clock)
			_, err := Verify(tc.request(), "us-east-1", lookup)
			var failed *Error
			if !errors.As(err, &failed) {
				t.Fatalf("got %v, want an *Error", err)
			}
			if failed.Code != tc.code || failed.Status != tc.status || !strings.Contains(failed.Message, tc.message) {
				t.Errorf("got %d %s %q; want %d %s containing %q", failed.Status, failed.Code, failed.Message, tc.status, tc.code, tc.message)
			}
		})
	}
}
