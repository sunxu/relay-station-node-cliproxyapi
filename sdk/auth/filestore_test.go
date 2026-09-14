package auth

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	accountv1 "github.com/router-for-me/CLIProxyAPI/v7/internal/accountmanagementv1"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

func TestFileTokenStoreSuccessfulAntigravitySaveDoesNotLogSecrets(t *testing.T) {
	baseDir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)

	var captured bytes.Buffer
	previousOutput := log.StandardLogger().Out
	log.SetOutput(&captured)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	const (
		accessCanary  = "native-access-token-canary-stage7n"
		refreshCanary = "native-refresh-token-canary-stage7n"
	)
	auth := &cliproxyauth.Auth{
		ID:       "antigravity-native-secret@example.com.json",
		FileName: "antigravity-native-secret@example.com.json",
		Provider: "antigravity",
		Metadata: map[string]any{
			"type":          "antigravity",
			"email":         "native-secret@example.com",
			"access_token":  accessCanary,
			"refresh_token": refreshCanary,
		},
	}
	path, err := store.Save(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(persisted, []byte(accessCanary)) || !bytes.Contains(persisted, []byte(refreshCanary)) {
		t.Fatal("native persistence did not commit the credential fields")
	}
	restarted := NewFileTokenStore()
	restarted.SetBaseDir(baseDir)
	reloaded, err := restarted.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded) != 1 || reloaded[0].Provider != "antigravity" || reloaded[0].FileName != auth.FileName {
		t.Fatalf("native persistence restart projection=%+v", reloaded)
	}
	for _, canary := range []string{accessCanary, refreshCanary, baseDir, path} {
		if strings.Contains(captured.String(), canary) {
			t.Fatalf("native persistence log leaked protected canary %q", canary)
		}
	}
}

func TestFileTokenStoreAntigravitySaveUsesCoordinatorGateAndBookkeeping(t *testing.T) {
	baseDir := t.TempDir()
	coordinator, err := accountv1.ForAuthDir(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := coordinator.Gate().Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	auth := &cliproxyauth.Auth{
		ID:       "antigravity-user@example.com.json",
		FileName: "antigravity-user@example.com.json",
		Provider: "antigravity",
		Metadata: map[string]any{"type": "antigravity", "email": "user@example.com", "access_token": "token"},
	}
	done := make(chan error, 1)
	go func() {
		_, saveErr := store.Save(context.Background(), auth)
		done <- saveErr
	}()
	select {
	case err := <-done:
		t.Fatalf("Save bypassed coordinator gate: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	lease.Release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	marker, err := coordinator.Bookkeeping().Load(auth.FileName)
	if err != nil {
		t.Fatal(err)
	}
	if marker.TargetIncarnation == "" {
		t.Fatal("new native save did not provision an incarnation")
	}
}

func TestFileTokenStoreAntigravitySaveHeldLeaseAndDeleteMarker(t *testing.T) {
	baseDir := t.TempDir()
	coordinator, err := accountv1.ForAuthDir(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := coordinator.Gate().Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx := accountv1.WithHeldLease(context.Background(), lease)
	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	auth := &cliproxyauth.Auth{
		ID:       "antigravity-held@example.com.json",
		FileName: "antigravity-held@example.com.json",
		Provider: "antigravity",
		Metadata: map[string]any{"type": "antigravity", "email": "held@example.com", "access_token": "token"},
	}
	path, err := store.Save(ctx, auth)
	if err != nil {
		lease.Release()
		t.Fatal(err)
	}
	markerName := auth.FileName
	if _, err := coordinator.Bookkeeping().Load(markerName); err != nil {
		lease.Release()
		t.Fatal(err)
	}
	gateReady := make(chan struct{})
	go func() {
		other, acquireErr := coordinator.Gate().Acquire(context.Background())
		if acquireErr != nil {
			return
		}
		close(gateReady)
		other.Release()
	}()
	select {
	case <-gateReady:
		lease.Release()
		t.Fatal("Save released the outer held lease")
	case <-time.After(30 * time.Millisecond):
	}
	lease.Release()

	if err := store.Delete(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Bookkeeping().Load(markerName); !os.IsNotExist(err) {
		t.Fatalf("marker was not removed, err=%v", err)
	}
}

func TestFileTokenStoreAntigravityExistingSavePreservesIncarnationAndClearsProof(t *testing.T) {
	baseDir := t.TempDir()
	coordinator, err := accountv1.ForAuthDir(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	fileName := "antigravity-existing@example.com.json"
	auth := &cliproxyauth.Auth{
		ID:       fileName,
		FileName: fileName,
		Provider: "antigravity",
		Metadata: map[string]any{"type": "antigravity", "email": "existing@example.com", "access_token": "first"},
	}
	if _, err := store.Save(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	marker, err := coordinator.Bookkeeping().Load(fileName)
	if err != nil {
		t.Fatal(err)
	}
	incarnation := marker.TargetIncarnation
	token, err := accountv1.NewWriteToken()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(baseDir, fileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Bookkeeping().RecordWrite(fileName, "antigravity", "existing@example.com", content, token); err != nil {
		t.Fatal(err)
	}

	auth.Metadata["access_token"] = "second"
	if _, err := store.Save(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	marker, err = coordinator.Bookkeeping().Load(fileName)
	if err != nil {
		t.Fatal(err)
	}
	if marker.TargetIncarnation != incarnation {
		t.Fatalf("Save changed existing incarnation: got %q, want %q", marker.TargetIncarnation, incarnation)
	}
	if marker.ContentSHA256V1 != "" || marker.WriteTokenV1 != "" || marker.PostconditionProofV1 != "" {
		t.Fatalf("native Save retained operation proof: %+v", marker)
	}
}

func TestFileTokenStoreAntigravityDeleteRecreateGetsNewIncarnation(t *testing.T) {
	baseDir := t.TempDir()
	coordinator, err := accountv1.ForAuthDir(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	fileName := "antigravity-recreate@example.com.json"
	newAuth := func(token string) *cliproxyauth.Auth {
		return &cliproxyauth.Auth{
			ID:       fileName,
			FileName: fileName,
			Provider: "antigravity",
			Metadata: map[string]any{"type": "antigravity", "email": "recreate@example.com", "access_token": token},
		}
	}
	path, err := store.Save(context.Background(), newAuth("first"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := coordinator.Bookkeeping().Load(fileName)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Bookkeeping().Load(fileName); !os.IsNotExist(err) {
		t.Fatalf("marker survived delete: %v", err)
	}
	if _, err := store.Save(context.Background(), newAuth("second")); err != nil {
		t.Fatal(err)
	}
	second, err := coordinator.Bookkeeping().Load(fileName)
	if err != nil {
		t.Fatal(err)
	}
	if second.TargetIncarnation == first.TargetIncarnation {
		t.Fatalf("recreated file reused incarnation %q", second.TargetIncarnation)
	}
}

func TestFileTokenStoreAntigravityGateCancellationPropagates(t *testing.T) {
	baseDir := t.TempDir()
	coordinator, err := accountv1.ForAuthDir(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := coordinator.Gate().Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	_, err = store.Save(ctx, &cliproxyauth.Auth{
		ID:       "antigravity-canceled@example.com.json",
		FileName: "antigravity-canceled@example.com.json",
		Provider: "antigravity",
		Metadata: map[string]any{"type": "antigravity", "email": "canceled@example.com", "access_token": "token"},
	})
	if err == nil {
		t.Fatal("Save succeeded despite canceled gate acquisition")
	}
}

func TestExtractAccessToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata map[string]any
		expected string
	}{
		{
			"antigravity top-level access_token",
			map[string]any{"access_token": "tok-abc"},
			"tok-abc",
		},
		{
			"gemini nested token.access_token",
			map[string]any{
				"token": map[string]any{"access_token": "tok-nested"},
			},
			"tok-nested",
		},
		{
			"top-level takes precedence over nested",
			map[string]any{
				"access_token": "tok-top",
				"token":        map[string]any{"access_token": "tok-nested"},
			},
			"tok-top",
		},
		{
			"empty metadata",
			map[string]any{},
			"",
		},
		{
			"whitespace-only access_token",
			map[string]any{"access_token": "   "},
			"",
		},
		{
			"wrong type access_token",
			map[string]any{"access_token": 12345},
			"",
		},
		{
			"token is not a map",
			map[string]any{"token": "not-a-map"},
			"",
		},
		{
			"nested whitespace-only",
			map[string]any{
				"token": map[string]any{"access_token": "  "},
			},
			"",
		},
		{
			"fallback to nested when top-level empty",
			map[string]any{
				"access_token": "",
				"token":        map[string]any{"access_token": "tok-fallback"},
			},
			"tok-fallback",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractAccessToken(tt.metadata)
			if got != tt.expected {
				t.Errorf("extractAccessToken() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFileTokenStoreSaveExistingMetadataSetsFileAttributes(t *testing.T) {
	tests := []struct {
		name          string
		existingToken string
		savedToken    string
	}{
		{name: "unchanged content", existingToken: "token", savedToken: "token"},
		{name: "overwritten content", existingToken: "old-token", savedToken: "new-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseDir := t.TempDir()
			fileName := "antigravity-user.json"
			path := filepath.Join(baseDir, fileName)
			existing := []byte(`{"type":"antigravity","access_token":"` + tt.existingToken + `","disabled":false}`)
			if errWrite := os.WriteFile(path, existing, 0o600); errWrite != nil {
				t.Fatalf("write existing auth file: %v", errWrite)
			}

			store := NewFileTokenStore()
			store.SetBaseDir(baseDir)
			auth := &cliproxyauth.Auth{
				ID:       fileName,
				FileName: fileName,
				Metadata: map[string]any{
					"type":         "antigravity",
					"access_token": tt.savedToken,
				},
			}

			savedPath, errSave := store.Save(context.Background(), auth)
			if errSave != nil {
				t.Fatalf("Save() error = %v", errSave)
			}
			if savedPath != path {
				t.Fatalf("Save() path = %q, want %q", savedPath, path)
			}
			if got := auth.Attributes[cliproxyauth.AttributePath]; got != path {
				t.Errorf("path attribute = %q, want %q", got, path)
			}
			if got := auth.Attributes[cliproxyauth.AttributeSource]; got != path {
				t.Errorf("source attribute = %q, want %q", got, path)
			}
			if got := auth.Attributes[cliproxyauth.AttributeSourceBackend]; got != cliproxyauth.AuthSourceFile {
				t.Errorf("source backend attribute = %q, want %q", got, cliproxyauth.AuthSourceFile)
			}
			persisted, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatalf("read saved auth file: %v", errRead)
			}
			expected := []byte(`{"type":"antigravity","access_token":"` + tt.savedToken + `","disabled":false}`)
			if !jsonEqual(persisted, expected) {
				t.Errorf("saved auth file = %s, want JSON equal to %s", persisted, expected)
			}
		})
	}
}

func TestFileTokenStoreNormalizesLegacyCredentialMetadata(t *testing.T) {
	t.Run("save", func(t *testing.T) {
		baseDir := t.TempDir()
		store := NewFileTokenStore()
		store.SetBaseDir(baseDir)
		auth := &cliproxyauth.Auth{
			ID:       "legacy-save.json",
			FileName: "legacy-save.json",
			Metadata: map[string]any{
				"type":            "codex",
				"request-retry":   2,
				"request_retry":   0,
				"disable-cooling": true,
			},
		}

		path, errSave := store.Save(context.Background(), auth)
		if errSave != nil {
			t.Fatalf("Save() error = %v", errSave)
		}
		persisted, errRead := os.ReadFile(path)
		if errRead != nil {
			t.Fatalf("read saved auth file: %v", errRead)
		}
		want := []byte(`{"type":"codex","request_retry":0,"disable_cooling":true,"disabled":false}`)
		if !jsonEqual(persisted, want) {
			t.Fatalf("saved auth file = %s, want JSON equal to %s", persisted, want)
		}
	})

	t.Run("list", func(t *testing.T) {
		baseDir := t.TempDir()
		path := filepath.Join(baseDir, "legacy-list.json")
		if errWrite := os.WriteFile(path, []byte(`{"type":"codex","request-retry":2,"disable-cooling":true}`), 0o600); errWrite != nil {
			t.Fatalf("write legacy auth file: %v", errWrite)
		}
		store := NewFileTokenStore()
		store.SetBaseDir(baseDir)

		auths, errList := store.List(context.Background())
		if errList != nil {
			t.Fatalf("List() error = %v", errList)
		}
		if len(auths) != 1 {
			t.Fatalf("List() len = %d, want 1", len(auths))
		}
		if got := auths[0].Metadata["request_retry"]; got != float64(2) {
			t.Fatalf("listed request_retry = %#v, want 2", got)
		}
		if got := auths[0].Metadata["disable_cooling"]; got != true {
			t.Fatalf("listed disable_cooling = %#v, want true", got)
		}
		for _, legacy := range []string{"request-retry", "disable-cooling"} {
			if _, exists := auths[0].Metadata[legacy]; exists {
				t.Fatalf("listed metadata retained %q: %#v", legacy, auths[0].Metadata)
			}
		}
	})
}

func TestFileTokenStoreSaveRejectsInvalidWeight(t *testing.T) {
	baseDir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	auth := &cliproxyauth.Auth{
		ID:       "invalid.json",
		FileName: "invalid.json",
		Metadata: map[string]any{
			"type":                       "test",
			cliproxyauth.AttributeWeight: 1.5,
		},
	}

	if _, errSave := store.Save(context.Background(), auth); errSave == nil {
		t.Fatal("Save() accepted an invalid weight")
	}
	if _, errStat := os.Stat(filepath.Join(baseDir, auth.FileName)); !os.IsNotExist(errStat) {
		t.Fatalf("invalid auth file was persisted: %v", errStat)
	}
}

func TestFileTokenStoreListSkipsInvalidPluginSourceWeight(t *testing.T) {
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "plugin.json")
	if errWrite := os.WriteFile(path, []byte(`{"type":"plugin","weight":"invalid"}`), 0o600); errWrite != nil {
		t.Fatalf("write auth file: %v", errWrite)
	}

	parserCalled := false
	RegisterPluginAuthParser(fileStoreMultiAuthParserFunc(func(context.Context, pluginapi.AuthParseRequest) ([]*cliproxyauth.Auth, bool, error) {
		parserCalled = true
		return []*cliproxyauth.Auth{{ID: "plugin.json", Provider: "plugin"}}, true, nil
	}))
	t.Cleanup(func() {
		RegisterPluginAuthParser(nil)
	})

	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	auths, errList := store.List(context.Background())
	if errList != nil {
		t.Fatalf("List() error = %v", errList)
	}
	if parserCalled {
		t.Fatal("plugin parser was called for an invalid persisted source")
	}
	if len(auths) != 0 {
		t.Fatalf("List() returned invalid plugin auths: %#v", auths)
	}
}

func TestFileTokenStoreListExpandsPluginMultiAuths(t *testing.T) {
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "geminicli.json")
	if errWrite := os.WriteFile(path, []byte(`{"type":"gemini-cli","weight":3,"headers":{"X-Test":"value"}}`), 0o600); errWrite != nil {
		t.Fatalf("write auth file: %v", errWrite)
	}

	RegisterPluginAuthParser(fileStoreMultiAuthParserFunc(func(ctx context.Context, req pluginapi.AuthParseRequest) ([]*cliproxyauth.Auth, bool, error) {
		if req.Provider != "gemini-cli" || req.Path != path || req.FileName != "geminicli.json" {
			t.Fatalf("ParseAuths request = %#v, want file context", req)
		}
		return []*cliproxyauth.Auth{
			{
				ID:       "geminicli.json",
				Provider: "gemini-cli",
				Metadata: map[string]any{
					"type": "gemini-cli",
					"headers": map[string]any{
						"X-Test": "value",
					},
				},
			},
			nil,
			{
				ID:       "geminicli-project-a.json",
				Provider: "gemini-cli",
				Metadata: map[string]any{
					"type":       "gemini-cli",
					"project_id": "project-a",
					"headers": map[string]any{
						"X-Test": "value",
					},
				},
			},
		}, true, nil
	}))
	t.Cleanup(func() {
		RegisterPluginAuthParser(nil)
	})

	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	auths, errList := store.List(context.Background())
	if errList != nil {
		t.Fatalf("List() error = %v", errList)
	}
	if len(auths) != 2 {
		t.Fatalf("List() len = %d, want two plugin auths", len(auths))
	}
	if firstIndex, secondIndex := auths[0].EnsureIndex(), auths[1].EnsureIndex(); firstIndex == "" || firstIndex == secondIndex {
		t.Fatalf("auth indexes = %q/%q, want distinct non-empty indexes", firstIndex, secondIndex)
	}
	for _, auth := range auths {
		if !cliproxyauth.IsPluginVirtualAuth(auth) {
			t.Fatalf("auth attributes = %#v, want plugin virtual marker", auth.Attributes)
		}
		if auth.Attributes[cliproxyauth.AttributeVirtualSource] != path {
			t.Fatalf("virtual_source = %q, want %q", auth.Attributes[cliproxyauth.AttributeVirtualSource], path)
		}
		if auth.Attributes["path"] != path || auth.Attributes["source"] != path {
			t.Fatalf("auth attributes = %#v, want source path", auth.Attributes)
		}
		if gotHeader := auth.Attributes["header:X-Test"]; gotHeader != "value" {
			t.Fatalf("header:X-Test = %q, want value", gotHeader)
		}
		if gotWeight := auth.Attributes[cliproxyauth.AttributeWeight]; gotWeight != "3" {
			t.Fatalf("weight = %q, want 3", gotWeight)
		}
	}
	if gotProject := auths[1].Metadata["project_id"]; gotProject != "project-a" {
		t.Fatalf("project_id = %#v, want project-a", gotProject)
	}
}

func TestFileTokenStoreListAppliesSourceDisabledToPluginMultiAuths(t *testing.T) {
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "geminicli.json")
	if errWrite := os.WriteFile(path, []byte(`{"type":"gemini-cli","disabled":true}`), 0o600); errWrite != nil {
		t.Fatalf("write auth file: %v", errWrite)
	}

	RegisterPluginAuthParser(fileStoreMultiAuthParserFunc(func(context.Context, pluginapi.AuthParseRequest) ([]*cliproxyauth.Auth, bool, error) {
		return []*cliproxyauth.Auth{
			{ID: "geminicli.json", Provider: "gemini-cli", Metadata: map[string]any{"type": "gemini-cli"}},
			{ID: "geminicli-project-a.json", Provider: "gemini-cli", Metadata: map[string]any{"type": "gemini-cli", "project_id": "project-a"}},
		}, true, nil
	}))
	t.Cleanup(func() {
		RegisterPluginAuthParser(nil)
	})

	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	auths, errList := store.List(context.Background())
	if errList != nil {
		t.Fatalf("List() error = %v", errList)
	}
	if len(auths) != 2 {
		t.Fatalf("List() len = %d, want two plugin auths", len(auths))
	}
	for _, auth := range auths {
		if !auth.Disabled || auth.Status != cliproxyauth.StatusDisabled {
			t.Fatalf("auth %s disabled/status = %v/%s, want disabled", auth.ID, auth.Disabled, auth.Status)
		}
		if got, _ := auth.Metadata["disabled"].(bool); !got {
			t.Fatalf("auth %s metadata disabled = %#v, want true", auth.ID, auth.Metadata["disabled"])
		}
	}
}

func TestFileTokenStoreListPluginHandledEmptySuppressesBuiltin(t *testing.T) {
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "codex.json")
	if errWrite := os.WriteFile(path, []byte(`{"type":"codex","access_token":"token"}`), 0o600); errWrite != nil {
		t.Fatalf("write auth file: %v", errWrite)
	}

	RegisterPluginAuthParser(fileStoreMultiAuthParserFunc(func(context.Context, pluginapi.AuthParseRequest) ([]*cliproxyauth.Auth, bool, error) {
		return nil, true, nil
	}))
	t.Cleanup(func() {
		RegisterPluginAuthParser(nil)
	})

	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	auths, errList := store.List(context.Background())
	if errList != nil {
		t.Fatalf("List() error = %v", errList)
	}
	if len(auths) != 0 {
		t.Fatalf("List() len = %d, want plugin-handled empty result", len(auths))
	}
}

type fileStoreMultiAuthParserFunc func(context.Context, pluginapi.AuthParseRequest) ([]*cliproxyauth.Auth, bool, error)

func (f fileStoreMultiAuthParserFunc) ParseAuth(context.Context, pluginapi.AuthParseRequest) (*cliproxyauth.Auth, bool, error) {
	return nil, false, nil
}

func (f fileStoreMultiAuthParserFunc) ParseAuths(ctx context.Context, req pluginapi.AuthParseRequest) ([]*cliproxyauth.Auth, bool, error) {
	return f(ctx, req)
}
