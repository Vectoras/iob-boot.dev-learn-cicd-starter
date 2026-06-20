package auth

import (
	"errors"
	"net/http"
	"testing"
)

var ErrMalformedHeader = errors.New("malformed authorization header")

func errEqual(a, b error) bool {
	if a == nil || b == nil {
		return a == b
	}

	return a.Error() == b.Error()
}

// ---

func TestGetAPIKey(t *testing.T) {

	type test struct {
		headers    http.Header
		wantResult string
		wantErr    error
	}

	tests := map[string]test{
		"missing auth header": {
			http.Header{},
			"",
			ErrNoAuthHeaderIncluded,
		},
		"empty auth header": {
			http.Header{"Authorization": {""}},
			"",
			ErrNoAuthHeaderIncluded,
		},
		"bad auth header": {
			http.Header{"Authorization": {"somebadauthheader"}},
			"",
			ErrMalformedHeader,
		},
		"good auth header": {
			http.Header{"Authorization": {"ApiKey someapikey"}},
			"someapikey",
			nil,
		},
	}

	for tName, tc := range tests {
		got, err := GetAPIKey(tc.headers)
		if got != tc.wantResult || !errEqual(err, tc.wantErr) {
			t.Errorf("%s: got (%q, %v), want(%q, %v)", tName, got, err, tc.wantResult, tc.wantErr)
		}
	}

}
