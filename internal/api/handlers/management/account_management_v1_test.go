package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	accountv1 "github.com/router-for-me/CLIProxyAPI/v7/internal/accountmanagementv1"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

func newAccountV1TestHandler(t *testing.T) (*Handler, string) {
	t.Helper()
	dir := t.TempDir()
	store := sdkAuth.NewFileTokenStore()
	store.SetBaseDir(dir)
	manager := coreauth.NewManager(store, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	h.tokenStore = store
	return h, dir
}

func newUnsupportedAccountV1TestHandler(t *testing.T) (*Handler, string) {
	t.Helper()
	dir := t.TempDir()
	store := &accountV1UnsupportedStore{}
	manager := coreauth.NewManager(store, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	h.tokenStore = store
	return h, dir
}

type accountV1UnsupportedStore struct{}

func (*accountV1UnsupportedStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }
func (*accountV1UnsupportedStore) Save(context.Context, *coreauth.Auth) (string, error) {
	return "", nil
}
func (*accountV1UnsupportedStore) Delete(context.Context, string) error { return nil }

func antigravityCredential(t *testing.T, email, access string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"type": "antigravity", "access_token": access, "refresh_token": "refresh-canary",
		"expires_in": 3600, "timestamp": 1770000000000, "expired": "2026-09-14T00:00:00Z",
		"email": email, "project_id": "project-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func accountJSONCall(t *testing.T, handler gin.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	body = accountMutationTestRequest(body)
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	c.Request.Header.Set("Content-Type", "application/json")
	handler(c)
	return recorder
}

func accountMultipartCall(t *testing.T, handler gin.HandlerFunc, request any, credential []byte) *httptest.ResponseRecorder {
	t.Helper()
	request = accountMutationTestRequest(request)
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	requestHeader := make(map[string][]string)
	requestHeader["Content-Disposition"] = []string{`form-data; name="request"`}
	requestHeader["Content-Type"] = []string{"application/json"}
	p, err := w.CreatePart(textprotoMIMEHeader(requestHeader))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.NewEncoder(p).Encode(request); err != nil {
		t.Fatal(err)
	}
	credentialHeader := make(map[string][]string)
	credentialHeader["Content-Disposition"] = []string{`form-data; name="credential"; filename="ignored.json"`}
	credentialHeader["Content-Type"] = []string{"application/json"}
	p, err = w.CreatePart(textprotoMIMEHeader(credentialHeader))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Write(credential); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/", &body)
	c.Request.Header.Set("Content-Type", w.FormDataContentType())
	handler(c)
	return recorder
}

func accountMutationTestRequest(input any) any {
	request, ok := input.(map[string]any)
	if !ok {
		return input
	}
	if _, mutation := request["mutation_budget_ms"]; !mutation {
		return input
	}
	copyRequest := make(map[string]any, len(request)+1)
	for key, value := range request {
		copyRequest[key] = value
	}
	if _, exists := copyRequest["dispatch_token_v1"]; !exists {
		copyRequest["dispatch_token_v1"] = uuid.NewString()
	}
	return copyRequest
}

// textprotoMIMEHeader keeps the test helper local without obscuring the exact
// two-part wire format under a higher-level form helper.
func textprotoMIMEHeader(values map[string][]string) textproto.MIMEHeader {
	return textproto.MIMEHeader(values)
}

func decodeAccountResponse(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
	return body
}

func TestAccountContractV1AdvertisesOnlyWithFileStoreAndProvisionedSidecars(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, dir := newAccountV1TestHandler(t)
	credential := antigravityCredential(t, "user@example.com", "access-canary")
	if err := os.WriteFile(filepath.Join(dir, "antigravity-user@example.com.json"), credential, 0o600); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	h.GetAccountContractV1(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("capability status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "access-canary") || strings.Contains(recorder.Body.String(), "refresh-canary") || strings.Contains(recorder.Body.String(), dir) {
		t.Fatalf("capability response leaked protected data: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), accountMutationCapability) {
		t.Fatalf("capability missing from %s", recorder.Body.String())
	}
	coordinator, _ := accountv1.ForAuthDir(dir)
	if _, err := coordinator.Bookkeeping().Load("antigravity-user@example.com.json"); err != nil {
		t.Fatalf("legacy sidecar was not provisioned: %v", err)
	}

	h.tokenStore = &accountV1UnsupportedStore{}
	recorder = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(recorder)
	h.GetAccountContractV1(c)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unsupported store advertised v1: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	resolve := accountJSONCall(t, h.ResolveAccountTargetV1, map[string]any{"provider": "antigravity", "email": "user@example.com"})
	if resolve.Code != http.StatusServiceUnavailable || !strings.Contains(resolve.Body.String(), "manager_unavailable") {
		t.Fatalf("unsupported store executed resolve: status=%d body=%s", resolve.Code, resolve.Body.String())
	}
	create := accountMultipartCall(t, h.CreateAccountV1, map[string]any{"mode": "create"}, antigravityCredential(t, "blocked@example.com", "blocked"))
	if create.Code != http.StatusServiceUnavailable || !strings.Contains(create.Body.String(), "manager_unavailable") {
		t.Fatalf("unsupported store executed mutation: status=%d body=%s", create.Code, create.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "antigravity-blocked@example.com.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported store mutation changed filesystem: %v", err)
	}
}

func TestMutationPartialReturnsCurrentRecoveryEvidence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, dir := newAccountV1TestHandler(t)
	email := "partial@example.com"
	filename := "antigravity-" + email + ".json"
	credential := antigravityCredential(t, email, "partial-access")
	if err := os.WriteFile(filepath.Join(dir, filename), credential, 0o600); err != nil {
		t.Fatal(err)
	}
	coordinator, err := accountv1.ForAuthDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := coordinator.Gate().Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	writeToken, err := accountv1.NewWriteToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coordinator.Bookkeeping().RecordWrite(filename, "antigravity", email, credential, writeToken); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	h.writePartialAccountV1(c, coordinator, accountTargetInputV1{Provider: "antigravity", Email: email, Name: filename}, lease)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("partial status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := decodeAccountResponse(t, recorder)
	if precondition, ok := body["target_precondition_v1"].(string); !ok || accountv1.ValidateTargetPrecondition(precondition) != nil {
		t.Fatalf("partial response lacks valid target precondition: %#v", body)
	}
	post, ok := body["postcondition_v1"].(map[string]any)
	if !ok || post["write_token_v1"] != writeToken || post["postcondition_proof_v1"] == "" {
		t.Fatalf("partial response lacks committed postcondition: %#v", body)
	}

	// A credential commit followed by a marker-commit failure leaves the old
	// marker stale. Recovery must still return current pt1 and suppress proof.
	changed := antigravityCredential(t, email, "changed-after-marker")
	if err = os.WriteFile(filepath.Join(dir, filename), changed, 0o600); err != nil {
		t.Fatal(err)
	}
	lease, err = coordinator.Gate().Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(recorder)
	h.writePartialAccountV1(c, coordinator, accountTargetInputV1{Provider: "antigravity", Email: email, Name: filename}, lease)
	body = decodeAccountResponse(t, recorder)
	if precondition, ok := body["target_precondition_v1"].(string); !ok || accountv1.ValidateTargetPrecondition(precondition) != nil {
		t.Fatalf("stale-marker partial lacks current precondition: %#v", body)
	}
	if body["postcondition_v1"] != nil {
		t.Fatalf("stale marker produced false postcondition: %#v", body)
	}
}

func TestAccountV1ErrorTruncationPreservesUTF8(t *testing.T) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", strings.Repeat("界", 100))
	if !utf8.Valid(recorder.Body.Bytes()) {
		t.Fatalf("error response is not valid UTF-8: %q", recorder.Body.Bytes())
	}
	var body struct {
		Error accountV1Error `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Error.Message) > 256 {
		t.Fatalf("bounded message has %d bytes", len(body.Error.Message))
	}
}

func TestResolveProvesQuiescenceThroughSharedMutationGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, dir := newAccountV1TestHandler(t)
	email := "quiescence@example.com"
	filename := "antigravity-" + email + ".json"
	if err := os.WriteFile(filepath.Join(dir, filename), antigravityCredential(t, email, "quiescence-access"), 0o600); err != nil {
		t.Fatal(err)
	}
	coordinator, err := accountv1.ForAuthDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coordinator.Bookkeeping().Provision(filename, "antigravity", email); err != nil {
		t.Fatal(err)
	}
	activeMutation, err := coordinator.Gate().Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		raw := []byte(`{"provider":"antigravity","email":"quiescence@example.com"}`)
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
		c.Request.Header.Set("Content-Type", "application/json")
		h.ResolveAccountTargetV1(c)
		result <- recorder
	}()

	select {
	case recorder := <-result:
		activeMutation.Release()
		t.Fatalf("resolve passed active mutation gate: status=%d body=%s", recorder.Code, recorder.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	activeMutation.Release()
	select {
	case recorder := <-result:
		if recorder.Code != http.StatusOK {
			t.Fatalf("resolve after mutation release status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolve did not complete after prior mutation released the shared gate")
	}
}

func TestRecoveryResolveDurablyFencesLateMutationAcrossRestart(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, dir := newAccountV1TestHandler(t)
	const (
		email = "late-dispatch@example.com"
		token = "00000000-0000-4000-8000-000000000042"
	)

	recovery := accountJSONCall(t, h.ResolveAccountTargetV1, map[string]any{
		"provider":                "antigravity",
		"email":                   email,
		"fence_dispatch_token_v1": token,
	})
	if recovery.Code != http.StatusOK {
		t.Fatalf("fenced recovery status=%d body=%s", recovery.Code, recovery.Body.String())
	}

	absent, err := accountv1.EncodeTargetPrecondition("absent", "antigravity", email, "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	credential := antigravityCredential(t, email, "late-dispatch-access")
	content, err := accountv1.EncodeContentProof(credential)
	if err != nil {
		t.Fatal(err)
	}
	writeToken, err := accountv1.NewWriteToken()
	if err != nil {
		t.Fatal(err)
	}
	late := accountMultipartCall(t, h.CreateAccountV1, map[string]any{
		"mode":                   "create",
		"provider":               "antigravity",
		"email":                  email,
		"target_precondition_v1": absent,
		"dispatch_token_v1":      token,
		"write_token_v1":         writeToken,
		"content_sha256_v1":      content,
		"mutation_budget_ms":     15000,
	}, credential)
	if late.Code != http.StatusConflict || !strings.Contains(late.Body.String(), "mutation_dispatch_fenced") || !strings.Contains(late.Body.String(), `"physical_commit":"not_started"`) {
		t.Fatalf("late mutation was not fenced: status=%d body=%s", late.Code, late.Body.String())
	}
	if _, err = os.Stat(filepath.Join(dir, "antigravity-"+email+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("late mutation changed credential state: %v", err)
	}
	lateInvalidTarget := accountJSONCall(t, h.DisableAccountV1, map[string]any{
		"dispatch_token_v1":  token,
		"target":             map[string]any{"provider": "unsupported"},
		"mutation_budget_ms": 15000,
	})
	if lateInvalidTarget.Code != http.StatusConflict || !strings.Contains(lateInvalidTarget.Body.String(), "mutation_dispatch_fenced") {
		t.Fatalf("target validation ran before dispatch fence: status=%d body=%s", lateInvalidTarget.Code, lateInvalidTarget.Body.String())
	}

	restarted, err := accountv1.NewDispatchFenceStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.RequireUnfenced(token); !errors.Is(err, accountv1.ErrDispatchFenced) {
		t.Fatalf("restart lost dispatch fence: %v", err)
	}
}

func TestAccountV1CreateResolveStatusReplaceAndRemove(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, dir := newAccountV1TestHandler(t)
	email := "user@example.com"
	absent, err := accountv1.EncodeTargetPrecondition("absent", "antigravity", email, "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	firstCredential := antigravityCredential(t, email, "access-one")
	firstContent, _ := accountv1.EncodeContentProof(firstCredential)
	firstToken, _ := accountv1.NewWriteToken()
	create := map[string]any{"mode": "create", "provider": "antigravity", "email": email, "target_precondition_v1": absent, "write_token_v1": firstToken, "content_sha256_v1": firstContent, "mutation_budget_ms": 15000}
	recorder := accountMultipartCall(t, h.CreateAccountV1, create, firstCredential)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	created := decodeAccountResponse(t, recorder)
	target := created["target"].(map[string]any)
	if target["name"] != "antigravity-user@example.com.json" || target["disabled"] != false {
		t.Fatalf("unexpected target: %#v", target)
	}
	if strings.Contains(recorder.Body.String(), "access-one") || strings.Contains(recorder.Body.String(), "refresh-canary") || strings.Contains(recorder.Body.String(), dir) {
		t.Fatalf("create response leaked protected data: %s", recorder.Body.String())
	}

	resolved := accountJSONCall(t, h.ResolveAccountTargetV1, map[string]any{"provider": "antigravity", "email": email})
	if resolved.Code != http.StatusOK {
		t.Fatalf("resolve status=%d body=%s", resolved.Code, resolved.Body.String())
	}
	resolution := decodeAccountResponse(t, resolved)
	resolvedTarget := resolution["target"].(map[string]any)
	inputTarget := map[string]any{"provider": "antigravity", "email": email, "name": resolvedTarget["name"], "auth_index": resolvedTarget["auth_index"], "target_precondition_v1": resolution["target_precondition_v1"]}
	disable := accountJSONCall(t, h.DisableAccountV1, map[string]any{"target": inputTarget, "mutation_budget_ms": 15000})
	if disable.Code != http.StatusOK || decodeAccountResponse(t, disable)["result"] != "applied" {
		t.Fatalf("disable status=%d body=%s", disable.Code, disable.Body.String())
	}
	resolveDisabled := accountJSONCall(t, h.ResolveAccountTargetV1, map[string]any{"provider": "antigravity", "email": email})
	disabledBody := decodeAccountResponse(t, resolveDisabled)
	if disabledBody["target"].(map[string]any)["disabled"] != true {
		t.Fatalf("disabled state not durable: %s", resolveDisabled.Body.String())
	}

	replaceTarget := disabledBody["target"].(map[string]any)
	replaceInput := map[string]any{"provider": "antigravity", "email": email, "name": replaceTarget["name"], "auth_index": replaceTarget["auth_index"], "target_precondition_v1": disabledBody["target_precondition_v1"]}
	secondCredential := antigravityCredential(t, email, "access-two")
	secondContent, _ := accountv1.EncodeContentProof(secondCredential)
	secondToken, _ := accountv1.NewWriteToken()
	replace := accountMultipartCall(t, h.ReplaceAccountV1, map[string]any{"mode": "replace", "target": replaceInput, "write_token_v1": secondToken, "content_sha256_v1": secondContent, "mutation_budget_ms": 15000}, secondCredential)
	if replace.Code != http.StatusOK {
		t.Fatalf("replace status=%d body=%s", replace.Code, replace.Body.String())
	}
	if strings.Contains(replace.Body.String(), "access-two") {
		t.Fatalf("replace response leaked credential: %s", replace.Body.String())
	}
	replaceBody := decodeAccountResponse(t, replace)
	thirdToken, _ := accountv1.NewWriteToken()
	replacedTarget := replaceBody["target"].(map[string]any)
	sameTarget := map[string]any{"provider": replacedTarget["provider"], "email": replacedTarget["email"], "name": replacedTarget["name"], "auth_index": replacedTarget["auth_index"], "target_precondition_v1": replaceBody["target_precondition_v1"]}
	sameReplace := accountMultipartCall(t, h.ReplaceAccountV1, map[string]any{"mode": "replace", "target": sameTarget, "write_token_v1": thirdToken, "content_sha256_v1": secondContent, "mutation_budget_ms": 15000}, secondCredential)
	if sameReplace.Code != http.StatusOK {
		t.Fatalf("same-content replace status=%d body=%s", sameReplace.Code, sameReplace.Body.String())
	}
	sameBody := decodeAccountResponse(t, sameReplace)
	if sameBody["target_precondition_v1"] != replaceBody["target_precondition_v1"] {
		t.Fatal("same-content replace unnecessarily changed target precondition")
	}
	post := sameBody["postcondition_v1"].(map[string]any)
	if post["write_token_v1"] != thirdToken || post["write_token_v1"] == secondToken {
		t.Fatalf("same-content replace did not publish new operation proof: %#v", post)
	}

	current := accountJSONCall(t, h.ResolveAccountTargetV1, map[string]any{"provider": "antigravity", "email": email})
	currentBody := decodeAccountResponse(t, current)
	currentTarget := currentBody["target"].(map[string]any)
	remove := accountJSONCall(t, h.RemoveAccountV1, map[string]any{"target": map[string]any{"provider": "antigravity", "email": email, "name": currentTarget["name"], "auth_index": currentTarget["auth_index"], "target_precondition_v1": currentBody["target_precondition_v1"]}, "mutation_budget_ms": 15000})
	if remove.Code != http.StatusOK {
		t.Fatalf("remove status=%d body=%s", remove.Code, remove.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "antigravity-user@example.com.json")); !os.IsNotExist(err) {
		t.Fatalf("credential survived remove: %v", err)
	}
}

func TestAccountV1RejectsStaleCASAndInvalidUploadWithoutMutation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, dir := newAccountV1TestHandler(t)
	email := "user@example.com"
	credential := antigravityCredential(t, email, "access-one")
	filename := "antigravity-user@example.com.json"
	if err := os.WriteFile(filepath.Join(dir, filename), credential, 0o600); err != nil {
		t.Fatal(err)
	}
	resolve := accountJSONCall(t, h.ResolveAccountTargetV1, map[string]any{"provider": "antigravity", "email": email})
	body := decodeAccountResponse(t, resolve)
	target := body["target"].(map[string]any)
	target["target_precondition_v1"] = strings.Repeat("x", 47)
	before, _ := os.ReadFile(filepath.Join(dir, filename))
	response := accountJSONCall(t, h.DisableAccountV1, map[string]any{"target": target, "mutation_budget_ms": 15000})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid precondition status=%d body=%s", response.Code, response.Body.String())
	}
	after, _ := os.ReadFile(filepath.Join(dir, filename))
	if !bytes.Equal(before, after) {
		t.Fatal("invalid precondition mutated credential")
	}

	absent, _ := accountv1.EncodeTargetPrecondition("absent", "antigravity", "other@example.com", "", "", "", nil)
	invalid := append(antigravityCredential(t, "other@example.com", "access"), []byte(` `)...)
	var object map[string]any
	_ = json.Unmarshal(bytes.TrimSpace(invalid), &object)
	object["headers"] = map[string]any{"X-Secret": "credential-canary"}
	invalid, _ = json.Marshal(object)
	content, _ := accountv1.EncodeContentProof(invalid)
	token, _ := accountv1.NewWriteToken()
	response = accountMultipartCall(t, h.CreateAccountV1, map[string]any{"mode": "create", "provider": "antigravity", "email": "other@example.com", "target_precondition_v1": absent, "write_token_v1": token, "content_sha256_v1": content, "mutation_budget_ms": 15000}, invalid)
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "upload_invalid") {
		t.Fatalf("invalid upload status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "credential-canary") {
		t.Fatalf("error leaked credential: %s", response.Body.String())
	}
}

func TestAccountV1RequestResponseAndLogsDoNotLeakSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const managementKey = "management-key-canary-stage7n"
	t.Setenv("MANAGEMENT_PASSWORD", managementKey)
	h, dir := newAccountV1TestHandler(t)

	var captured bytes.Buffer
	previousOutput := log.StandardLogger().Out
	log.SetOutput(&captured)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	engine := gin.New()
	engine.Use(gin.LoggerWithWriter(&captured))
	engine.POST("/v0/management/account-mutations/v1/create", h.V1BearerOnlyMiddleware(), h.CreateAccountV1)

	credential := []byte(`{"type":"antigravity","access_token":"access-token-canary-stage7n","refresh_token":"refresh-token-canary-stage7n","expires_in":3600,"timestamp":1770000000000,"expired":"2026-09-14T00:00:00Z","email":"secret-log@example.com","project_id":"project-a","forbidden_path":"/private/credential/path-canary-stage7n"}`)
	absent, err := accountv1.EncodeTargetPrecondition("absent", "antigravity", "secret-log@example.com", "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	content, err := accountv1.EncodeContentProof(credential)
	if err != nil {
		t.Fatal(err)
	}
	token, err := accountv1.NewWriteToken()
	if err != nil {
		t.Fatal(err)
	}
	requestBody := map[string]any{"mode": "create", "provider": "antigravity", "email": "secret-log@example.com", "target_precondition_v1": absent, "dispatch_token_v1": uuid.NewString(), "write_token_v1": token, "content_sha256_v1": content, "mutation_budget_ms": 15000}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	requestHeader := textproto.MIMEHeader{}
	requestHeader.Set("Content-Disposition", `form-data; name="request"`)
	requestHeader.Set("Content-Type", "application/json")
	requestPart, err := w.CreatePart(requestHeader)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.NewEncoder(requestPart).Encode(requestBody); err != nil {
		t.Fatal(err)
	}
	credentialHeader := textproto.MIMEHeader{}
	credentialHeader.Set("Content-Disposition", `form-data; name="credential"; filename="credential-canary-stage7n.json"`)
	credentialHeader.Set("Content-Type", "application/json")
	credentialPart, err := w.CreatePart(credentialHeader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = credentialPart.Write(credential); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v0/management/account-mutations/v1/create", &body)
	request.Header.Set("Content-Type", w.FormDataContentType())
	request.Header.Set("Authorization", "Bearer "+managementKey)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity || !strings.Contains(recorder.Body.String(), "upload_invalid") {
		t.Fatalf("invalid secret canary upload status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	observed := captured.String() + recorder.Body.String()
	for _, canary := range []string{managementKey, "access-token-canary-stage7n", "refresh-token-canary-stage7n", string(credential), "/private/credential/path-canary-stage7n", dir} {
		if strings.Contains(observed, canary) {
			t.Fatalf("management surface leaked protected canary %q", canary)
		}
	}
}

func TestAccountV1SuccessfulCreateReplaceDoNotLeakSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const managementKey = "management-key-success-canary"
	t.Setenv("MANAGEMENT_PASSWORD", managementKey)
	h, dir := newAccountV1TestHandler(t)

	var captured bytes.Buffer
	previousOutput := log.StandardLogger().Out
	log.SetOutput(&captured)
	t.Cleanup(func() { log.SetOutput(previousOutput) })
	engine := gin.New()
	engine.Use(gin.LoggerWithWriter(&captured))
	engine.POST("/create", h.V1BearerOnlyMiddleware(), h.CreateAccountV1)
	engine.POST("/replace", h.V1BearerOnlyMiddleware(), h.ReplaceAccountV1)
	engine.POST("/disable", h.V1BearerOnlyMiddleware(), h.DisableAccountV1)
	engine.POST("/enable", h.V1BearerOnlyMiddleware(), h.EnableAccountV1)
	engine.POST("/remove", h.V1BearerOnlyMiddleware(), h.RemoveAccountV1)
	responses := make([]string, 0, 5)
	callJSON := func(path string, payload map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		payload = accountMutationTestRequest(payload).(map[string]any)
		raw, errMarshal := json.Marshal(payload)
		if errMarshal != nil {
			t.Fatal(errMarshal)
		}
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+managementKey)
		result := httptest.NewRecorder()
		engine.ServeHTTP(result, req)
		responses = append(responses, result.Body.String())
		return result
	}

	email := "success-canary@example.com"
	credential := antigravityCredential(t, email, "successful-access-token-canary")
	absent, err := accountv1.EncodeTargetPrecondition("absent", "antigravity", email, "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	content, err := accountv1.EncodeContentProof(credential)
	if err != nil {
		t.Fatal(err)
	}
	token, err := accountv1.NewWriteToken()
	if err != nil {
		t.Fatal(err)
	}
	requestBody := map[string]any{"mode": "create", "provider": "antigravity", "email": email, "target_precondition_v1": absent, "write_token_v1": token, "content_sha256_v1": content, "mutation_budget_ms": 15000}
	body, contentType := accountMultipartBody(t, requestBody, credential)
	request := httptest.NewRequest(http.MethodPost, "/create", body)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Authorization", "Bearer "+managementKey)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("successful create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	responses = append(responses, recorder.Body.String())
	createBody := decodeAccountResponse(t, recorder)
	if strings.Contains(recorder.Body.String(), "successful-access-token-canary") || strings.Contains(recorder.Body.String(), dir) {
		t.Fatalf("create response leaked protected canary: %s", recorder.Body.String())
	}

	target := createBody["target"].(map[string]any)
	replaceCredential := antigravityCredential(t, email, "successful-replace-token-canary")
	replaceContent, err := accountv1.EncodeContentProof(replaceCredential)
	if err != nil {
		t.Fatal(err)
	}
	replaceToken, err := accountv1.NewWriteToken()
	if err != nil {
		t.Fatal(err)
	}
	replaceRequest := map[string]any{"mode": "replace", "target": map[string]any{"provider": target["provider"], "email": target["email"], "name": target["name"], "auth_index": target["auth_index"], "target_precondition_v1": createBody["target_precondition_v1"]}, "write_token_v1": replaceToken, "content_sha256_v1": replaceContent, "mutation_budget_ms": 15000}
	body, contentType = accountMultipartBody(t, replaceRequest, replaceCredential)
	request = httptest.NewRequest(http.MethodPost, "/replace", body)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Authorization", "Bearer "+managementKey)
	recorder = httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("successful replace status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	responses = append(responses, recorder.Body.String())
	if strings.Contains(recorder.Body.String(), "successful-replace-token-canary") || strings.Contains(recorder.Body.String(), dir) {
		t.Fatalf("replace response leaked protected canary: %s", recorder.Body.String())
	}

	replaceBody := decodeAccountResponse(t, recorder)
	currentTarget := replaceBody["target"].(map[string]any)
	mutationTarget := func(body map[string]any) map[string]any {
		return map[string]any{
			"provider":               currentTarget["provider"],
			"email":                  currentTarget["email"],
			"name":                   currentTarget["name"],
			"auth_index":             currentTarget["auth_index"],
			"target_precondition_v1": body["target_precondition_v1"],
		}
	}
	disabled := callJSON("/disable", map[string]any{"target": mutationTarget(replaceBody), "mutation_budget_ms": 15000})
	if disabled.Code != http.StatusOK {
		t.Fatalf("successful disable status=%d body=%s", disabled.Code, disabled.Body.String())
	}
	credentialPath := filepath.Join(dir, currentTarget["name"].(string))
	disabledRaw, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	var disabledCredential map[string]any
	if err = json.Unmarshal(disabledRaw, &disabledCredential); err != nil || disabledCredential["disabled"] != true {
		t.Fatalf("disable durable state=%v err=%v", disabledCredential["disabled"], err)
	}
	disabledBody := decodeAccountResponse(t, disabled)
	currentTarget = disabledBody["target"].(map[string]any)
	enabled := callJSON("/enable", map[string]any{"target": mutationTarget(disabledBody), "mutation_budget_ms": 15000})
	if enabled.Code != http.StatusOK {
		t.Fatalf("successful enable status=%d body=%s", enabled.Code, enabled.Body.String())
	}
	enabledRaw, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	var enabledCredential map[string]any
	if err = json.Unmarshal(enabledRaw, &enabledCredential); err != nil || enabledCredential["disabled"] != false {
		t.Fatalf("enable durable state=%v err=%v", enabledCredential["disabled"], err)
	}
	enabledBody := decodeAccountResponse(t, enabled)
	currentTarget = enabledBody["target"].(map[string]any)
	removed := callJSON("/remove", map[string]any{"target": mutationTarget(enabledBody), "mutation_budget_ms": 15000})
	if removed.Code != http.StatusOK {
		t.Fatalf("successful remove status=%d body=%s", removed.Code, removed.Body.String())
	}
	if _, err = os.Stat(credentialPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove left credential on disk: %v", err)
	}

	observed := captured.String() + strings.Join(responses, "")
	for _, canary := range []string{managementKey, "successful-access-token-canary", "successful-replace-token-canary", "refresh-canary", string(credential), string(replaceCredential), "ignored.json", dir, credentialPath} {
		if strings.Contains(observed, canary) {
			t.Fatalf("successful mutation surface leaked protected canary %q", canary)
		}
	}
}

func accountMultipartBody(t *testing.T, request any, credential []byte) (*bytes.Buffer, string) {
	t.Helper()
	request = accountMutationTestRequest(request)
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	requestHeader := textproto.MIMEHeader{}
	requestHeader.Set("Content-Disposition", `form-data; name="request"`)
	requestHeader.Set("Content-Type", "application/json")
	requestPart, err := w.CreatePart(requestHeader)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.NewEncoder(requestPart).Encode(request); err != nil {
		t.Fatal(err)
	}
	credentialHeader := textproto.MIMEHeader{}
	credentialHeader.Set("Content-Disposition", `form-data; name="credential"; filename="ignored.json"`)
	credentialHeader.Set("Content-Type", "application/json")
	credentialPart, err := w.CreatePart(credentialHeader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = credentialPart.Write(credential); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return &body, w.FormDataContentType()
}

func TestAccountV1CreateFilenameAdmission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _ := newAccountV1TestHandler(t)
	local238 := strings.Repeat("a", 226) + "@example.com" // 238 ASCII bytes.
	if len(local238) != 238 {
		t.Fatalf("test email length=%d", len(local238))
	}
	credential := antigravityCredential(t, local238, "access")
	absent, _ := accountv1.EncodeTargetPrecondition("absent", "antigravity", local238, "", "", "", nil)
	content, _ := accountv1.EncodeContentProof(credential)
	token, _ := accountv1.NewWriteToken()
	response := accountMultipartCall(t, h.CreateAccountV1, map[string]any{"mode": "create", "provider": "antigravity", "email": local238, "target_precondition_v1": absent, "write_token_v1": token, "content_sha256_v1": content, "mutation_budget_ms": 15000}, credential)
	if response.Code != http.StatusCreated {
		t.Fatalf("238-byte email status=%d body=%s", response.Code, response.Body.String())
	}

	local239 := strings.Repeat("b", 227) + "@example.com"
	credential = antigravityCredential(t, local239, "access")
	absent, _ = accountv1.EncodeTargetPrecondition("absent", "antigravity", local239, "", "", "", nil)
	content, _ = accountv1.EncodeContentProof(credential)
	token, _ = accountv1.NewWriteToken()
	response = accountMultipartCall(t, h.CreateAccountV1, map[string]any{"mode": "create", "provider": "antigravity", "email": local239, "target_precondition_v1": absent, "write_token_v1": token, "content_sha256_v1": content, "mutation_budget_ms": 15000}, credential)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("239-byte email status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAccountV1StatusNoopReconcilesRuntimeState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, dir := newAccountV1TestHandler(t)
	email := "status-noop@example.com"
	filename := "antigravity-" + email + ".json"
	credential := antigravityCredential(t, email, "status-noop-access")
	if err := os.WriteFile(filepath.Join(dir, filename), credential, 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := h.buildAuthFromFileData(filepath.Join(dir, filename), credential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.authManager.Register(coreauth.WithSkipPersist(context.Background()), auth); err != nil {
		t.Fatal(err)
	}
	coordinator, err := accountv1.ForAuthDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coordinator.Bookkeeping().Provision(filename, "antigravity", email); err != nil {
		t.Fatal(err)
	}
	resolved := accountJSONCall(t, h.ResolveAccountTargetV1, map[string]any{"provider": "antigravity", "email": email})
	resolvedBody := decodeAccountResponse(t, resolved)
	target := resolvedBody["target"].(map[string]any)
	input := accountTargetInputV1{Provider: target["provider"].(string), Email: target["email"].(string), Name: target["name"].(string), AuthIndex: target["auth_index"].(string), TargetPreconditionV1: resolvedBody["target_precondition_v1"].(string)}

	firstDisable := accountJSONCall(t, h.DisableAccountV1, map[string]any{"target": input, "mutation_budget_ms": 15000})
	if firstDisable.Code != http.StatusOK {
		t.Fatalf("initial disable status=%d body=%s", firstDisable.Code, firstDisable.Body.String())
	}
	before, err := os.ReadFile(filepath.Join(dir, filename))
	if err != nil {
		t.Fatal(err)
	}
	auth, ok := h.authManager.GetByID(auth.ID)
	if !ok {
		t.Fatal("runtime auth disappeared")
	}
	auth.Disabled = false
	auth.Status = coreauth.StatusActive
	if _, err = h.authManager.Update(coreauth.WithSkipPersist(context.Background()), auth); err != nil {
		t.Fatal(err)
	}

	resolved = accountJSONCall(t, h.ResolveAccountTargetV1, map[string]any{"provider": "antigravity", "email": email})
	resolvedBody = decodeAccountResponse(t, resolved)
	target = resolvedBody["target"].(map[string]any)
	input = accountTargetInputV1{Provider: target["provider"].(string), Email: target["email"].(string), Name: target["name"].(string), AuthIndex: target["auth_index"].(string), TargetPreconditionV1: resolvedBody["target_precondition_v1"].(string)}
	response := accountJSONCall(t, h.DisableAccountV1, map[string]any{"target": input, "mutation_budget_ms": 15000})
	if response.Code != http.StatusOK || decodeAccountResponse(t, response)["result"] != "applied" {
		t.Fatalf("stale runtime noop was not reconciled: status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "mutation_partial") || strings.Contains(response.Body.String(), "physical_commit") {
		t.Fatalf("runtime-only reconciliation reported physical commit: %s", response.Body.String())
	}
	after, err := os.ReadFile(filepath.Join(dir, filename))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("runtime-only reconciliation changed the durable credential")
	}
	if runtimeAuth := h.runtimeAuthForTargetV1(input); !runtimeAccountStatusMatchesV1(runtimeAuth, true) {
		t.Fatalf("runtime state did not converge: %#v", runtimeAuth)
	}

	resolved = accountJSONCall(t, h.ResolveAccountTargetV1, map[string]any{"provider": "antigravity", "email": email})
	resolvedBody = decodeAccountResponse(t, resolved)
	target = resolvedBody["target"].(map[string]any)
	input = accountTargetInputV1{Provider: target["provider"].(string), Email: target["email"].(string), Name: target["name"].(string), AuthIndex: target["auth_index"].(string), TargetPreconditionV1: resolvedBody["target_precondition_v1"].(string)}
	noop := accountJSONCall(t, h.DisableAccountV1, map[string]any{"target": input, "mutation_budget_ms": 15000})
	if noop.Code != http.StatusOK || decodeAccountResponse(t, noop)["result"] != "noop" {
		t.Fatalf("converged noop status=%d body=%s", noop.Code, noop.Body.String())
	}
}

func TestLegacyAntigravityOwnershipDependsOnSupportedStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, dir := newUnsupportedAccountV1TestHandler(t)
	email := "alternate-store@example.com"
	filename := "antigravity-" + email + ".json"
	credential := antigravityCredential(t, email, "alternate-store-access")
	if err := os.WriteFile(filepath.Join(dir, filename), credential, 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := h.buildAuthFromFileData(filepath.Join(dir, filename), credential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.authManager.Register(coreauth.WithSkipPersist(context.Background()), auth); err != nil {
		t.Fatal(err)
	}
	status := accountJSONCall(t, h.PatchAuthFileStatus, map[string]any{"name": filename, "auth_index": lockedAuthIndex(auth), "disabled": true})
	if status.Code == http.StatusConflict || strings.Contains(status.Body.String(), accountMutationV1RequiredError) {
		t.Fatalf("unsupported store incorrectly claimed v1 ownership: status=%d body=%s", status.Code, status.Body.String())
	}
	if status.Code != http.StatusOK {
		t.Fatalf("unsupported store legacy behavior failed: status=%d body=%s", status.Code, status.Body.String())
	}
}

func TestLegacyOwnershipDoesNotReopenWhenMetadataIsCorrupt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, dir := newAccountV1TestHandler(t)
	if err := os.WriteFile(filepath.Join(dir, "antigravity-corrupt.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	credential := antigravityCredential(t, "new-owner@example.com", "new-owner-access")
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/?name=new-owner.json", bytes.NewReader(credential))
	c.Request.Header.Set("Content-Type", "application/json")
	h.UploadAuthFile(c)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), accountMutationV1RequiredError) {
		t.Fatalf("corrupt metadata reopened legacy ownership: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAccountV1CredentialUploadBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _ := newAccountV1TestHandler(t)
	email := "large@example.com"
	absent, _ := accountv1.EncodeTargetPrecondition("absent", "antigravity", email, "", "", "", nil)
	token, _ := accountv1.NewWriteToken()
	credential := bytes.Repeat([]byte("x"), accountv1.MaxCredentialBytes+1)
	content, _ := accountv1.EncodeContentProof(credential)
	response := accountMultipartCall(t, h.CreateAccountV1, map[string]any{"mode": "create", "provider": "antigravity", "email": email, "target_precondition_v1": absent, "write_token_v1": token, "content_sha256_v1": content, "mutation_budget_ms": 15000}, credential)
	if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), "upload_too_large") {
		t.Fatalf("oversize upload status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAccountV1SlowMultipartReadTimesOutBeforeMutation(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the frozen five-second request read boundary")
	}
	gin.SetMode(gin.TestMode)
	h, dir := newAccountV1TestHandler(t)
	engine := gin.New()
	engine.POST("/create", h.CreateAccountV1)
	server := httptest.NewServer(engine)
	defer server.Close()

	pipeReader, pipeWriter := io.Pipe()
	multipartWriter := multipart.NewWriter(pipeWriter)
	startedWriting := make(chan struct{})
	go func() {
		defer pipeWriter.Close()
		close(startedWriting)
		requestHeader := textproto.MIMEHeader{}
		requestHeader.Set("Content-Disposition", `form-data; name="request"`)
		requestHeader.Set("Content-Type", "application/json")
		requestPart, err := multipartWriter.CreatePart(requestHeader)
		if err != nil {
			return
		}
		_, _ = requestPart.Write([]byte(`{"mode":"create","provider":"antigravity","email":"slow@example.com","target_precondition_v1":"pt1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","dispatch_token_v1":"00000000-0000-4000-8000-000000000001","write_token_v1":"wt1:AAAAAAAAAAAAAAAAAAAAAA","content_sha256_v1":"cs1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","mutation_budget_ms":15000}`))
		credentialHeader := textproto.MIMEHeader{}
		credentialHeader.Set("Content-Disposition", `form-data; name="credential"; filename="ignored.json"`)
		credentialHeader.Set("Content-Type", "application/json")
		credentialPart, err := multipartWriter.CreatePart(credentialHeader)
		if err != nil {
			return
		}
		_, _ = credentialPart.Write([]byte(`{"type":`))
		time.Sleep(accountv1.MaxRequestReadDuration + time.Second)
		_ = multipartWriter.Close()
	}()
	<-startedWriting
	request, err := http.NewRequest(http.MethodPost, server.URL+"/create", pipeReader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("slow request failed before bounded response: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusGatewayTimeout || !bytes.Contains(body, []byte("mutation_timeout")) {
		t.Fatalf("slow upload status=%d body=%s", response.StatusCode, body)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			t.Fatalf("slow upload created credential %s", entry.Name())
		}
	}
}

func TestLegacyAntigravityManagementMutationsRequireV1(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var captured bytes.Buffer
	previousOutput := log.StandardLogger().Out
	log.SetOutput(&captured)
	t.Cleanup(func() { log.SetOutput(previousOutput) })
	h, dir := newAccountV1TestHandler(t)
	credential := antigravityCredential(t, "legacy@example.com", "legacy-access-canary-stage7n")
	filename := "antigravity-legacy@example.com.json"
	if err := os.WriteFile(filepath.Join(dir, filename), credential, 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := h.buildAuthFromFileData(filepath.Join(dir, filename), credential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.authManager.Register(coreauth.WithSkipPersist(context.Background()), auth); err != nil {
		t.Fatal(err)
	}

	status := accountJSONCall(t, h.PatchAuthFileStatus, map[string]any{"name": filename, "auth_index": lockedAuthIndex(auth), "disabled": true})
	if status.Code != http.StatusConflict || !strings.Contains(status.Body.String(), accountMutationV1RequiredError) {
		t.Fatalf("legacy status=%d body=%s", status.Code, status.Body.String())
	}
	fields := accountJSONCall(t, h.PatchAuthFileFields, map[string]any{"name": filename, "auth_index": lockedAuthIndex(auth), "weight": 2})
	if fields.Code != http.StatusConflict || !strings.Contains(fields.Body.String(), accountMutationV1RequiredError) {
		t.Fatalf("legacy fields=%d body=%s", fields.Code, fields.Body.String())
	}

	deletion := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(deletion)
	c.Request = httptest.NewRequest(http.MethodDelete, "/?name="+filename, nil)
	h.DeleteAuthFile(c)
	if deletion.Code != http.StatusConflict || !strings.Contains(deletion.Body.String(), accountMutationV1RequiredError) {
		t.Fatalf("legacy delete=%d body=%s", deletion.Code, deletion.Body.String())
	}
	if _, err = os.Stat(filepath.Join(dir, filename)); err != nil {
		t.Fatalf("legacy rejection mutated credential: %v", err)
	}

	rawUpload := httptest.NewRecorder()
	c, _ = gin.CreateTestContext(rawUpload)
	c.Request = httptest.NewRequest(http.MethodPost, "/?name=raw-antigravity.json", bytes.NewReader(credential))
	c.Request.Header.Set("Content-Type", "application/json")
	h.UploadAuthFile(c)
	if rawUpload.Code != http.StatusConflict || !strings.Contains(rawUpload.Body.String(), accountMutationV1RequiredError) {
		t.Fatalf("legacy raw upload=%d body=%s", rawUpload.Code, rawUpload.Body.String())
	}
	if _, err = os.Stat(filepath.Join(dir, "raw-antigravity.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy raw upload mutated filesystem: %v", err)
	}

	deleteAll := httptest.NewRecorder()
	c, _ = gin.CreateTestContext(deleteAll)
	c.Request = httptest.NewRequest(http.MethodDelete, "/?all=true", nil)
	h.DeleteAuthFile(c)
	if deleteAll.Code != http.StatusConflict || !strings.Contains(deleteAll.Body.String(), accountMutationV1RequiredError) {
		t.Fatalf("legacy batch delete=%d body=%s", deleteAll.Code, deleteAll.Body.String())
	}
	if _, err = os.Stat(filepath.Join(dir, filename)); err != nil {
		t.Fatalf("legacy batch rejection mutated credential: %v", err)
	}
	observed := captured.String() + status.Body.String() + fields.Body.String() + deletion.Body.String() + rawUpload.Body.String() + deleteAll.Body.String()
	for _, canary := range []string{"legacy-access-canary-stage7n", "refresh-canary", string(credential), dir, filepath.Join(dir, filename)} {
		if strings.Contains(observed, canary) {
			t.Fatalf("legacy rejection surface leaked protected canary %q", canary)
		}
	}
}

func TestLegacyMultipartCannotHideAntigravityTypePastV1Limit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, dir := newAccountV1TestHandler(t)
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", `form-data; name="file"; filename="late-type.json"`)
	header.Set("Content-Type", "application/json")
	part, err := w.CreatePart(header)
	if err != nil {
		t.Fatal(err)
	}
	lateType := `{"padding":"` + strings.Repeat("x", accountMaxCredentialBytes+32) + `","type":"antigravity","email":"late@example.com"}`
	if _, err = part.Write([]byte(lateType)); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/", &body)
	c.Request.Header.Set("Content-Type", w.FormDataContentType())
	h.UploadAuthFile(c)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), accountMutationV1RequiredError) {
		t.Fatalf("late type status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if _, err = os.Stat(filepath.Join(dir, "late-type.json")); !os.IsNotExist(err) {
		t.Fatalf("legacy late-type upload mutated filesystem: %v", err)
	}
}
