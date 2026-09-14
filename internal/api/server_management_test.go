package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStage7NManagementRoutesAreRegisteredBehindBearerOnlyAuth(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-key")
	server := newTestServer(t)

	want := map[string]string{
		"GET /v0/management/account-contract/v1":           http.MethodGet,
		"POST /v0/management/account-targets/v1/resolve":   http.MethodPost,
		"POST /v0/management/account-mutations/v1/disable": http.MethodPost,
		"POST /v0/management/account-mutations/v1/enable":  http.MethodPost,
		"POST /v0/management/account-mutations/v1/remove":  http.MethodPost,
		"POST /v0/management/account-mutations/v1/create":  http.MethodPost,
		"POST /v0/management/account-mutations/v1/replace": http.MethodPost,
	}
	registered := make(map[string]bool)
	for _, route := range server.engine.Routes() {
		registered[route.Method+" "+route.Path] = true
	}
	for route := range want {
		if !registered[route] {
			t.Errorf("missing Stage 7N route %s", route)
		}
	}
	for _, route := range []string{
		"/v0/management/accounts",
		"/v0/management/account-operations",
		"/v0/management/account-admin",
	} {
		if registered[http.MethodGet+" "+route] || registered[http.MethodPost+" "+route] {
			t.Errorf("unexpected Stage 7B/Control route registered: %s", route)
		}
	}

	for route, method := range want {
		path := route[len(method)+1:]
		for name, headers := range map[string]map[string]string{
			"x-management-key":  {"X-Management-Key": "test-management-key"},
			"raw-authorization": {"Authorization": "test-management-key"},
		} {
			t.Run(name+" "+route, func(t *testing.T) {
				request := httptest.NewRequest(method, path, nil)
				for key, value := range headers {
					request.Header.Set(key, value)
				}
				recorder := httptest.NewRecorder()
				server.engine.ServeHTTP(recorder, request)
				if recorder.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
				}
			})
		}
	}

	unauthorized := httptest.NewRequest(http.MethodGet, "/v0/management/account-contract/v1", nil)
	unauthorizedRecorder := httptest.NewRecorder()
	server.engine.ServeHTTP(unauthorizedRecorder, unauthorized)
	if unauthorizedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing Bearer status = %d, want %d", unauthorizedRecorder.Code, http.StatusUnauthorized)
	}
	for _, header := range []string{"X-CPA-VERSION", "X-CPA-COMMIT", "X-CPA-BUILD-DATE", "X-CPA-SUPPORT-PLUGIN"} {
		if value := unauthorizedRecorder.Header().Get(header); value != "" {
			t.Fatalf("unauthenticated response disclosed %s=%q", header, value)
		}
	}

	legacy := httptest.NewRequest(http.MethodGet, "/v0/management/account-contract/v1", nil)
	legacy.Header.Set("X-Management-Key", "test-management-key")
	legacyRecorder := httptest.NewRecorder()
	server.engine.ServeHTTP(legacyRecorder, legacy)
	if legacyRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("X-Management-Key status = %d, want %d", legacyRecorder.Code, http.StatusUnauthorized)
	}

	authorized := httptest.NewRequest(http.MethodGet, "/v0/management/account-contract/v1", nil)
	authorized.Header.Set("Authorization", "Bearer test-management-key")
	authorizedRecorder := httptest.NewRecorder()
	server.engine.ServeHTTP(authorizedRecorder, authorized)
	if authorizedRecorder.Code != http.StatusOK {
		t.Fatalf("Bearer route status = %d, want %d", authorizedRecorder.Code, http.StatusOK)
	}
}
