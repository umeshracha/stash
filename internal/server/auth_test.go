package server

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A client that is refused must be told why, in the S3 error codes its SDK
// understands. Each request here fails before any signature is checked.
func TestAuthenticationFailuresNameTheirReason(t *testing.T) {
	s := &server{region: "us-east-1", credentials: map[string]credential{"app": {Secret: "a-long-enough-secret"}}}
	date := time.Now().UTC().Format("20060102T150405Z")
	authorization := func(key, region, sentAt string) *http.Request {
		r := httptest.NewRequest("GET", "/reports", nil)
		r.Header.Set("X-Amz-Date", sentAt)
		r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+key+"/"+sentAt[:8]+"/"+region+"/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature="+strings.Repeat("0", 64))
		return r
	}
	tests := []struct {
		name    string
		request *http.Request
		status  int
		code    string
	}{
		{"anonymous", httptest.NewRequest("GET", "/reports", nil), 403, "AccessDenied"},
		{"unknown access key", authorization("nobody", "us-east-1", date), 403, "InvalidAccessKeyId"},
		{"wrong region", authorization("app", "eu-west-1", date), 400, "AuthorizationHeaderMalformed"},
		{"clock an hour out", authorization("app", "us-east-1", time.Now().UTC().Add(-time.Hour).Format("20060102T150405Z")), 403, "RequestTimeTooSkewed"},
		{"wrong secret", authorization("app", "us-east-1", date), 403, "SignatureDoesNotMatch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.ServeHTTP(w, tc.request)
			var body struct {
				XMLName xml.Name `xml:"Error"`
				Code    string
				Message string
			}
			if err := xml.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not an S3 error: %v: %s", err, w.Body.String())
			}
			if w.Code != tc.status || body.Code != tc.code {
				t.Errorf("got %d %s (%s); want %d %s", w.Code, body.Code, body.Message, tc.status, tc.code)
			}
			if got := w.Header().Get("X-Amz-Bucket-Region"); got != "us-east-1" {
				t.Errorf("X-Amz-Bucket-Region = %q, want the server's region so an SDK can retry", got)
			}
		})
	}
}
