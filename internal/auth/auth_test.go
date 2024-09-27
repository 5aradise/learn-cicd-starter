package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		headers    http.Header
		wantAPIKey string
		wantErr    error
	}

	tests := make(map[string]test)

	normal := http.Header{}
	normal.Add("Authorization", "ApiKey 123")
	tests["normal"] = test{
		headers:    normal,
		wantAPIKey: "123",
		wantErr:    nil,
	}

	empty := http.Header{}
	tests["empty header"] = test{
		headers:    empty,
		wantAPIKey: "",
		wantErr:    ErrNoAuthHeaderIncluded,
	}

	emptyKey := http.Header{}
	emptyKey.Add("Authorization", "ApiKey ")
	tests["empty key"] = test{
		headers:    emptyKey,
		wantAPIKey: "",
		wantErr:    nil,
	}

	invalidLength := http.Header{}
	invalidLength.Add("Authorization", "ApiKey")
	tests["invalid header length"] = test{
		headers:    invalidLength,
		wantAPIKey: "",
		wantErr:    errors.New("malformed authorization header"),
	}

	invalidContent := http.Header{}
	invalidContent.Add("Authorization", "test test")
	tests["invalid header content"] = test{
		headers:    invalidContent,
		wantAPIKey: "",
		wantErr:    errors.New("malformed authorization heade"),
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotAPIKey, gotErr := GetAPIKey(tc.headers)
			if gotAPIKey != tc.wantAPIKey {
				t.Fatalf("test %s: expected: %v, %v; got: %v, %v", name, tc.wantAPIKey, tc.wantErr, gotAPIKey, gotErr)
			}
			if gotErr == nil && tc.wantErr != nil || gotErr != nil && tc.wantErr == nil {
				t.Fatalf("test %s: expected: %v, %v; got: %v, %v", name, tc.wantAPIKey, tc.wantErr, gotAPIKey, gotErr)
			} else {
				if gotErr != nil {
					if gotErr.Error() != tc.wantErr.Error() {
						t.Fatalf("test %s: expected: %v, %v; got: %v, %v", name, tc.wantAPIKey, tc.wantErr, gotAPIKey, gotErr)
					}
				}
			}
		})
	}
}
