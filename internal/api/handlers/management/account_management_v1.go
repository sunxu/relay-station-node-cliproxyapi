package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	accountv1 "github.com/router-for-me/CLIProxyAPI/v7/internal/accountmanagementv1"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/buildinfo"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginhost"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const (
	accountContractV1               = "v1"
	accountMaxCredentialBytes       = 262144
	accountMaxRequestReadDurationMS = 5000
	accountMaxMutationDurationMS    = 15000
	accountMaxQuiescenceDurationMS  = 25000
	accountMinPostCommitReserveMS   = 10000
	accountMutationV1RequiredError  = "account_mutation_v1_required"
	accountMutationCapability       = "management_account_mutation_v1"
	accountInventoryReadCapability  = "management_account_inventory_read"
)

type accountV1Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeAccountV1Error(c *gin.Context, status int, code, message string) {
	message = strings.ToValidUTF8(message, "")
	if len(message) > 256 {
		message = message[:256]
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
	}
	c.Header("Cache-Control", "no-store")
	c.AbortWithStatusJSON(status, gin.H{"error": accountV1Error{Code: code, Message: message}})
}

// V1BearerOnlyMiddleware applies the existing management-key verification and
// remote-access policy through the frozen Bearer-only v1 wire surface.
func (h *Handler) V1BearerOnlyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if c.GetHeader("X-Management-Key") != "" || !strings.HasPrefix(authorization, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer ")) == "" {
			writeAccountV1Error(c, http.StatusUnauthorized, "management_auth_required", "Bearer management authentication is required")
			return
		}
		clientIP := c.ClientIP()
		localClient := clientIP == "127.0.0.1" || clientIP == "::1"
		allowed, status, _ := h.AuthenticateManagementKey(clientIP, localClient, strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer ")))
		if !allowed {
			code := "management_auth_required"
			message := "management authentication failed"
			if status == http.StatusForbidden {
				code = "management_forbidden"
				message = "management access is forbidden"
			}
			writeAccountV1Error(c, status, code, message)
			return
		}
		c.Header("X-CPA-VERSION", buildinfo.Version)
		c.Header("X-CPA-COMMIT", buildinfo.Commit)
		c.Header("X-CPA-BUILD-DATE", buildinfo.BuildDate)
		c.Header("X-CPA-SUPPORT-PLUGIN", pluginhost.SupportPluginHeaderValue())
		c.Header("Cache-Control", "no-store")
		c.Next()
	}
}

// GetAccountContractV1 returns the frozen capability and budget projection.
func (h *Handler) GetAccountContractV1(c *gin.Context) {
	if !h.accountV1Ready() {
		writeAccountV1Error(c, http.StatusServiceUnavailable, "manager_unavailable", "account management contract is unavailable")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"contract": "node-account-management",
		"version":  accountContractV1,
		"capabilities": []string{
			accountInventoryReadCapability,
			accountMutationCapability,
		},
		"providers":                             []string{"antigravity"},
		"max_credential_bytes":                  accountMaxCredentialBytes,
		"max_request_read_duration_ms":          accountMaxRequestReadDurationMS,
		"max_mutation_duration_ms":              accountMaxMutationDurationMS,
		"max_quiescence_duration_ms":            accountMaxQuiescenceDurationMS,
		"min_post_commit_quiescence_reserve_ms": accountMinPostCommitReserveMS,
	})
}

type accountTargetInputV1 struct {
	Provider             string `json:"provider"`
	Email                string `json:"email"`
	Name                 string `json:"name"`
	AuthIndex            string `json:"auth_index"`
	TargetPreconditionV1 string `json:"target_precondition_v1"`
}

type accountMutationInputV1 struct {
	Mode                 string               `json:"mode,omitempty"`
	Provider             string               `json:"provider,omitempty"`
	Email                string               `json:"email,omitempty"`
	Target               accountTargetInputV1 `json:"target,omitempty"`
	TargetPreconditionV1 string               `json:"target_precondition_v1,omitempty"`
	DispatchTokenV1      string               `json:"dispatch_token_v1"`
	WriteTokenV1         string               `json:"write_token_v1,omitempty"`
	ContentSHA256V1      string               `json:"content_sha256_v1,omitempty"`
	MutationBudgetMS     int                  `json:"mutation_budget_ms"`
}

type accountTargetOutputV1 struct {
	Provider  string `json:"provider"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AuthIndex string `json:"auth_index"`
	Disabled  bool   `json:"disabled"`
}

type accountPostconditionOutputV1 struct {
	WriteTokenV1         string `json:"write_token_v1"`
	ContentSHA256V1      string `json:"content_sha256_v1"`
	PostconditionProofV1 string `json:"postcondition_proof_v1"`
}

func (h *Handler) accountV1Coordinator() (*accountv1.Coordinator, error) {
	if h == nil || h.cfg == nil || strings.TrimSpace(h.cfg.AuthDir) == "" || h.authManager == nil {
		return nil, errors.New("account management dependencies unavailable")
	}
	return accountv1.ForAuthDir(h.cfg.AuthDir)
}

func (h *Handler) accountV1Ready() bool {
	// The v1 sidecar and exact-filename durability contract is implemented by
	// the local filesystem store. Other native stores must not advertise the
	// capability until they implement the same gate and bookkeeping contract.
	if !h.accountV1StoreSupported() {
		return false
	}
	coordinator, err := h.accountV1Coordinator()
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), accountv1.MaxQuiescenceDuration)
	defer cancel()
	lease, err := coordinator.Gate().Acquire(ctx)
	if err != nil {
		return false
	}
	defer lease.Release()
	_, err = accountv1.ScanTargets(coordinator.AuthDir(), coordinator.Bookkeeping())
	return err == nil
}

func (h *Handler) accountV1StoreSupported() bool {
	if h == nil {
		return false
	}
	_, ok := h.tokenStore.(*sdkAuth.FileTokenStore)
	return ok
}

// accountMutationV1OwnershipActive is the single legacy-mutation ownership
// boundary. It intentionally does not inspect sidecar health: a corrupt or
// temporarily unavailable v1 metadata set must not reopen unsafe legacy
// Antigravity writers. Unsupported stores remain outside v1 ownership and
// retain their native legacy behavior.
func (h *Handler) accountMutationV1OwnershipActive() bool {
	return h != nil && h.cfg != nil && strings.TrimSpace(h.cfg.AuthDir) != "" && h.authManager != nil && h.accountV1StoreSupported()
}

func decodeAccountJSONV1(c *gin.Context, out any, limit int64, started time.Time) error {
	if c == nil || c.ContentType() != "application/json" {
		return errors.New("content type must be application/json")
	}
	controller := http.NewResponseController(c.Writer)
	_ = controller.SetReadDeadline(started.Add(accountv1.MaxRequestReadDuration))
	defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request contains trailing data")
	}
	return nil
}

func (h *Handler) acquireAccountV1(c *gin.Context, started time.Time, duration time.Duration) (*accountv1.Coordinator, *accountv1.Lease, context.Context, context.CancelFunc, bool) {
	if !h.accountV1StoreSupported() {
		writeAccountV1Error(c, http.StatusServiceUnavailable, "manager_unavailable", "account management contract is unavailable")
		return nil, nil, nil, nil, false
	}
	coordinator, err := h.accountV1Coordinator()
	if err != nil {
		writeAccountV1Error(c, http.StatusServiceUnavailable, "manager_unavailable", "account manager is unavailable")
		return nil, nil, nil, nil, false
	}
	gateCtx, cancelGate := context.WithDeadline(c.Request.Context(), started.Add(duration))
	lease, err := coordinator.Gate().Acquire(gateCtx)
	cancelGate()
	if err != nil {
		writeAccountV1Error(c, http.StatusGatewayTimeout, "mutation_timeout", "account mutation timed out")
		return nil, nil, nil, nil, false
	}
	requestCtx, cancelRequest := context.WithDeadline(c.Request.Context(), started.Add(accountv1.MaxQuiescenceDuration))
	return coordinator, lease, accountv1.WithHeldLease(requestCtx, lease), cancelRequest, true
}

// ResolveAccountTargetV1 resolves one sanitized target while entering the same
// FIFO gate used by mutations. A successful response is therefore also a
// remote quiescence observation for earlier admitted requests.
func (h *Handler) ResolveAccountTargetV1(c *gin.Context) {
	started := time.Now()
	coordinator, lease, _, cancel, ok := h.acquireAccountV1(c, started, accountv1.MaxQuiescenceDuration)
	if !ok {
		return
	}
	defer cancel()
	defer lease.Release()
	var request struct {
		Provider             string `json:"provider"`
		Email                string `json:"email"`
		FenceDispatchTokenV1 string `json:"fence_dispatch_token_v1,omitempty"`
	}
	if err := decodeAccountJSONV1(c, &request, 32*1024, started); err != nil {
		if accountReadTimedOut(started, err) {
			lease.Release()
			writeAccountTimeoutV1(c)
			return
		}
		writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "invalid target request")
		return
	}
	provider, email := normalizeAccountIdentity(request.Provider, request.Email)
	if provider != "antigravity" || email == "" {
		writeAccountV1Error(c, http.StatusBadRequest, "unsupported_provider", "provider is not supported")
		return
	}
	if request.FenceDispatchTokenV1 != "" {
		if err := accountv1.ValidateDispatchToken(request.FenceDispatchTokenV1); err != nil {
			writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "invalid dispatch fence token")
			return
		}
		if err := coordinator.DispatchFences().Fence(request.FenceDispatchTokenV1); err != nil {
			writeAccountV1Error(c, http.StatusServiceUnavailable, "target_metadata_unavailable", "dispatch fence could not be persisted")
			return
		}
	}
	targets, err := accountv1.ScanTargets(coordinator.AuthDir(), coordinator.Bookkeeping())
	if err != nil {
		writeAccountV1Error(c, http.StatusServiceUnavailable, "target_metadata_unavailable", "target metadata is unavailable")
		return
	}
	h.attachAccountIndexes(targets)
	target, err := accountv1.ResolveTarget(targets, provider, email)
	if errors.Is(err, accountv1.ErrTargetNotFound) {
		precondition, errAbsent := accountv1.EncodeTargetPrecondition("absent", provider, email, "", "", "", nil)
		if errAbsent != nil {
			writeAccountV1Error(c, http.StatusInternalServerError, "internal_error", "failed to resolve target")
			return
		}
		lease.Release()
		c.JSON(http.StatusOK, gin.H{"contract_version": accountContractV1, "present": false, "target": nil, "target_precondition_v1": precondition})
		return
	}
	if errors.Is(err, accountv1.ErrTargetAmbiguous) {
		writeAccountV1Error(c, http.StatusConflict, "auth_target_ambiguous", "multiple targets match the requested identity")
		return
	}
	if err != nil {
		writeAccountV1Error(c, http.StatusInternalServerError, "internal_error", "failed to resolve target")
		return
	}
	response := h.resolvedAccountV1(coordinator, target)
	lease.Release()
	c.JSON(http.StatusOK, response)
}

func normalizeAccountIdentity(provider, email string) (string, string) {
	return strings.ToLower(strings.TrimSpace(provider)), strings.ToLower(strings.TrimSpace(email))
}

func (h *Handler) attachAccountIndexes(targets []accountv1.Target) {
	if h == nil || h.authManager == nil {
		return
	}
	for i := range targets {
		for _, auth := range h.authManager.List() {
			if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), targets[i].Provider) || !strings.EqualFold(strings.TrimSpace(auth.FileName), targets[i].BackingFilename) {
				continue
			}
			if value, _ := auth.Metadata["email"].(string); !strings.EqualFold(strings.TrimSpace(value), targets[i].Email) {
				continue
			}
			targets[i].AuthIndex = lockedAuthIndex(auth)
			raw, err := os.ReadFile(filepath.Join(h.cfg.AuthDir, targets[i].BackingFilename))
			if err == nil {
				targets[i].TargetPrecondition, _ = accountv1.EncodeTargetPrecondition("present", targets[i].Provider, targets[i].Email, targets[i].TargetIncarnation, targets[i].BackingFilename, targets[i].AuthIndex, raw)
			}
			break
		}
	}
}

func (h *Handler) resolvedAccountV1(coordinator *accountv1.Coordinator, target accountv1.Target) gin.H {
	response := gin.H{
		"contract_version":       accountContractV1,
		"present":                true,
		"target":                 accountTargetOutputV1{Provider: target.Provider, Email: target.Email, Name: target.BackingFilename, AuthIndex: target.AuthIndex, Disabled: target.Disabled},
		"target_precondition_v1": target.TargetPrecondition,
		"postcondition_v1":       nil,
	}
	marker := target.Marker
	if marker != nil && marker.WriteTokenV1 != "" && marker.ContentSHA256V1 != "" && marker.PostconditionProofV1 != "" {
		raw, err := os.ReadFile(filepath.Join(coordinator.AuthDir(), target.BackingFilename))
		if err == nil {
			content, _ := accountv1.EncodeContentProof(raw)
			proof, errProof := accountv1.EncodePostcondition(marker.TargetIncarnation, target.Provider, target.Email, target.BackingFilename, raw, marker.WriteTokenV1)
			if errProof == nil && accountv1.ConstantTimeEqual(content, marker.ContentSHA256V1) && accountv1.ConstantTimeEqual(proof, marker.PostconditionProofV1) {
				response["postcondition_v1"] = accountPostconditionOutputV1{WriteTokenV1: marker.WriteTokenV1, ContentSHA256V1: marker.ContentSHA256V1, PostconditionProofV1: marker.PostconditionProofV1}
			}
		}
	}
	return response
}

func (h *Handler) DisableAccountV1(c *gin.Context) { h.mutateAccountStatusV1(c, true) }
func (h *Handler) EnableAccountV1(c *gin.Context)  { h.mutateAccountStatusV1(c, false) }

func validateMutationDispatchV1(c *gin.Context, coordinator *accountv1.Coordinator, lease *accountv1.Lease, token string) bool {
	if accountv1.ValidateDispatchToken(token) != nil {
		writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "invalid dispatch token")
		return false
	}
	if err := coordinator.DispatchFences().RequireUnfenced(token); err != nil {
		if errors.Is(err, accountv1.ErrDispatchFenced) {
			lease.Release()
			c.Header("Cache-Control", "no-store")
			c.JSON(http.StatusConflict, gin.H{
				"error":           accountV1Error{Code: "mutation_dispatch_fenced", Message: "this mutation dispatch is durably fenced"},
				"quiescent":       true,
				"physical_commit": "not_started",
			})
			return false
		}
		writeAccountV1Error(c, http.StatusServiceUnavailable, "target_metadata_unavailable", "dispatch fence metadata is unavailable")
		return false
	}
	return true
}

func (h *Handler) mutateAccountStatusV1(c *gin.Context, disabled bool) {
	started := time.Now()
	coordinator, lease, ctx, cancel, ok := h.acquireAccountV1(c, started, accountv1.MaxMutationDuration)
	if !ok {
		return
	}
	defer cancel()
	defer lease.Release()
	var request accountMutationInputV1
	if err := decodeAccountJSONV1(c, &request, 32*1024, started); err != nil {
		if accountReadTimedOut(started, err) {
			lease.Release()
			writeAccountTimeoutV1(c)
			return
		}
		writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "invalid mutation request")
		return
	}
	if !validateMutationDispatchV1(c, coordinator, lease, request.DispatchTokenV1) {
		return
	}
	if request.MutationBudgetMS < 1 || request.MutationBudgetMS > accountMaxMutationDurationMS {
		writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "invalid mutation request")
		return
	}
	if !h.validateMutationTargetV1(c, coordinator, request.Target, nil) {
		return
	}
	path := filepath.Join(coordinator.AuthDir(), request.Target.Name)
	raw, err := os.ReadFile(path)
	if err != nil {
		writeAccountV1Error(c, http.StatusNotFound, "auth_target_not_found", "target does not exist")
		return
	}
	var metadata map[string]any
	if json.Unmarshal(raw, &metadata) != nil {
		writeAccountV1Error(c, http.StatusUnprocessableEntity, "upload_invalid", "target credential is invalid")
		return
	}
	current, _ := metadata["disabled"].(bool)
	if current == disabled {
		result := "noop"
		if runtimeChanged, errRuntime := h.reconcileRuntimeStatusV1(ctx, path, raw, request.Target, disabled); errRuntime != nil {
			lease.Release()
			writeAccountV1Error(c, http.StatusServiceUnavailable, "manager_unavailable", "runtime account state could not be reconciled")
			return
		} else if runtimeChanged {
			result = "applied"
		}
		response, responseOK := h.buildCurrentMutationResponseV1(coordinator, request.Target, result, nil)
		if !responseOK {
			lease.Release()
			writeAccountV1Error(c, http.StatusServiceUnavailable, "target_metadata_unavailable", "target metadata is unavailable")
			return
		}
		lease.Release()
		c.JSON(http.StatusOK, response)
		return
	}
	if !mayStartAccountCommit(ctx, started, request.MutationBudgetMS) {
		lease.Release()
		writeAccountTimeoutV1(c)
		return
	}
	metadata["disabled"] = disabled
	next, err := json.Marshal(metadata)
	if err != nil {
		writeAccountV1Error(c, http.StatusInternalServerError, "internal_error", "failed to encode credential")
		return
	}
	if err = atomicWriteAccountCredential(path, next); err != nil {
		if errors.Is(err, errAccountPhysicalCommitted) {
			h.writePartialAccountV1(c, coordinator, request.Target, lease)
		} else {
			writeAccountV1Error(c, http.StatusInternalServerError, "internal_error", "failed to persist credential")
		}
		return
	}
	if _, err = coordinator.Bookkeeping().RecordNativeRefresh(request.Target.Name, next); err != nil {
		h.writePartialAccountV1(c, coordinator, request.Target, lease)
		return
	}
	auth, err := h.buildAuthFromFileData(path, next)
	if err != nil {
		h.writePartialAccountV1(c, coordinator, request.Target, lease)
		return
	}
	if err = h.upsertAuthRecord(coreauth.WithSkipPersist(ctx), auth); err != nil {
		h.writePartialAccountV1(c, coordinator, request.Target, lease)
		return
	}
	response, responseOK := h.buildCurrentMutationResponseV1(coordinator, request.Target, "applied", nil)
	if !responseOK {
		h.writePartialAccountV1(c, coordinator, request.Target, lease)
		return
	}
	lease.Release()
	c.JSON(http.StatusOK, response)
}

func (h *Handler) runtimeAuthForTargetV1(input accountTargetInputV1) *coreauth.Auth {
	if h == nil || h.authManager == nil {
		return nil
	}
	provider, email := normalizeAccountIdentity(input.Provider, input.Email)
	for _, auth := range h.authManager.List() {
		if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), provider) || !strings.EqualFold(strings.TrimSpace(auth.FileName), strings.TrimSpace(input.Name)) {
			continue
		}
		value, _ := auth.Metadata["email"].(string)
		if !strings.EqualFold(strings.TrimSpace(value), email) || lockedAuthIndex(auth) != strings.TrimSpace(input.AuthIndex) {
			continue
		}
		return auth
	}
	return nil
}

func runtimeAccountStatusMatchesV1(auth *coreauth.Auth, disabled bool) bool {
	if auth == nil || auth.Disabled != disabled {
		return false
	}
	if disabled {
		return auth.Status == coreauth.StatusDisabled
	}
	return auth.Status != coreauth.StatusDisabled
}

// reconcileRuntimeStatusV1 returns true when runtime state had to change. It
// is used only after the durable file already has the requested value, so any
// failure here is pre-commit and must never be reported as mutation_partial.
func (h *Handler) reconcileRuntimeStatusV1(ctx context.Context, path string, raw []byte, input accountTargetInputV1, disabled bool) (bool, error) {
	if runtimeAccountStatusMatchesV1(h.runtimeAuthForTargetV1(input), disabled) {
		return false, nil
	}
	auth, err := h.buildAuthFromFileData(path, raw)
	if err != nil {
		return false, err
	}
	applyAuthDisabledState(auth, disabled)
	if err = h.upsertAuthRecord(coreauth.WithSkipPersist(ctx), auth); err != nil {
		return false, err
	}
	if !runtimeAccountStatusMatchesV1(h.runtimeAuthForTargetV1(input), disabled) {
		return false, errors.New("runtime account state did not converge")
	}
	return true, nil
}

func (h *Handler) RemoveAccountV1(c *gin.Context) {
	started := time.Now()
	coordinator, lease, ctx, cancel, ok := h.acquireAccountV1(c, started, accountv1.MaxMutationDuration)
	if !ok {
		return
	}
	defer cancel()
	defer lease.Release()
	var request accountMutationInputV1
	if err := decodeAccountJSONV1(c, &request, 32*1024, started); err != nil {
		if accountReadTimedOut(started, err) {
			lease.Release()
			writeAccountTimeoutV1(c)
			return
		}
		writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "invalid mutation request")
		return
	}
	if !validateMutationDispatchV1(c, coordinator, lease, request.DispatchTokenV1) {
		return
	}
	if request.MutationBudgetMS < 1 || request.MutationBudgetMS > accountMaxMutationDurationMS {
		writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "invalid mutation request")
		return
	}
	var target accountv1.Target
	if !h.validateMutationTargetV1(c, coordinator, request.Target, &target) {
		return
	}
	if !mayStartAccountCommit(ctx, started, request.MutationBudgetMS) {
		lease.Release()
		writeAccountTimeoutV1(c)
		return
	}
	path := filepath.Join(coordinator.AuthDir(), target.BackingFilename)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeAccountV1Error(c, http.StatusNotFound, "auth_target_not_found", "target does not exist")
		} else {
			writeAccountV1Error(c, http.StatusInternalServerError, "internal_error", "failed to remove credential")
		}
		return
	}
	if err := syncAccountDirectory(coordinator.AuthDir()); err != nil {
		h.writePartialAccountV1(c, coordinator, request.Target, lease)
		return
	}
	if err := coordinator.Bookkeeping().Delete(target.BackingFilename); err != nil {
		h.writePartialAccountV1(c, coordinator, request.Target, lease)
		return
	}
	h.removeAuthsForPath(coreauth.WithSkipPersist(ctx), path, "")
	absent, _ := accountv1.EncodeTargetPrecondition("absent", target.Provider, target.Email, "", "", "", nil)
	lease.Release()
	c.JSON(http.StatusOK, gin.H{"contract_version": accountContractV1, "result": "applied", "quiescent": true, "target": nil, "target_precondition_v1": absent, "postcondition_v1": nil})
}

func (h *Handler) CreateAccountV1(c *gin.Context)  { h.mutateUploadedAccountV1(c, true) }
func (h *Handler) ReplaceAccountV1(c *gin.Context) { h.mutateUploadedAccountV1(c, false) }

func (h *Handler) mutateUploadedAccountV1(c *gin.Context, create bool) {
	started := time.Now()
	coordinator, lease, ctx, cancel, ok := h.acquireAccountV1(c, started, accountv1.MaxMutationDuration)
	if !ok {
		return
	}
	defer cancel()
	defer lease.Release()
	request, credential, err := readAccountMultipartV1(c, started)
	if err != nil {
		if accountReadTimedOut(started, err) {
			lease.Release()
			writeAccountTimeoutV1(c)
		} else if accountUploadTooLarge(err) {
			writeAccountV1Error(c, http.StatusRequestEntityTooLarge, "upload_too_large", "credential upload is too large")
		} else {
			writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "invalid multipart request")
		}
		return
	}
	if !validateMutationDispatchV1(c, coordinator, lease, request.DispatchTokenV1) {
		return
	}
	if request.MutationBudgetMS < 1 || request.MutationBudgetMS > accountMaxMutationDurationMS || accountv1.ValidateWriteToken(request.WriteTokenV1) != nil || accountv1.ValidateContentProof(request.ContentSHA256V1) != nil {
		writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "invalid mutation request")
		return
	}
	actualContent, _ := accountv1.EncodeContentProof(credential)
	if !accountv1.ConstantTimeEqual(actualContent, request.ContentSHA256V1) {
		writeAccountV1Error(c, http.StatusUnprocessableEntity, "upload_invalid", "credential content proof does not match")
		return
	}
	parsed, err := accountv1.ParseAntigravityCredential(credential)
	if err != nil {
		writeAccountV1Error(c, http.StatusUnprocessableEntity, "upload_invalid", "credential is invalid")
		return
	}
	var filename, incarnation string
	if create {
		provider, email := normalizeAccountIdentity(request.Provider, request.Email)
		if request.Mode != "create" || provider != "antigravity" || email != parsed.Email || len([]byte(email)) > accountv1.MaxCreateEmailBytes {
			writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "invalid create identity")
			return
		}
		filename = "antigravity-" + email + ".json"
		if len([]byte(filename)) > accountv1.MaxBackingFilenameBytes {
			writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "create filename is too long")
			return
		}
		targets, errScan := accountv1.ScanTargets(coordinator.AuthDir(), coordinator.Bookkeeping())
		if errScan != nil {
			writeAccountV1Error(c, http.StatusServiceUnavailable, "target_metadata_unavailable", "target metadata is unavailable")
			return
		}
		if _, errResolve := accountv1.ResolveTarget(targets, provider, email); errResolve == nil || !errors.Is(errResolve, accountv1.ErrTargetNotFound) {
			writeAccountV1Error(c, http.StatusConflict, "auth_target_exists", "target already exists")
			return
		}
		absent, _ := accountv1.EncodeTargetPrecondition("absent", provider, email, "", "", "", nil)
		if !accountv1.ConstantTimeEqual(absent, request.TargetPreconditionV1) {
			writeAccountV1Error(c, http.StatusConflict, "auth_target_changed", "target changed")
			return
		}
		if _, errStat := os.Stat(filepath.Join(coordinator.AuthDir(), filename)); !errors.Is(errStat, os.ErrNotExist) {
			writeAccountV1Error(c, http.StatusConflict, "auth_target_exists", "target already exists")
			return
		}
		incarnation, err = accountv1.NewIncarnation()
		if err != nil {
			writeAccountV1Error(c, http.StatusInternalServerError, "internal_error", "failed to create target metadata")
			return
		}
	} else {
		if request.Mode != "replace" || !h.validateMutationTargetV1(c, coordinator, request.Target, nil) {
			return
		}
		targetProvider, targetEmail := normalizeAccountIdentity(request.Target.Provider, request.Target.Email)
		if parsed.Email != targetEmail || targetProvider != "antigravity" {
			writeAccountV1Error(c, http.StatusUnprocessableEntity, "identity_mismatch", "credential identity does not match target")
			return
		}
		filename = request.Target.Name
		marker, errLoad := coordinator.Bookkeeping().Load(filename)
		if errLoad != nil {
			writeAccountV1Error(c, http.StatusServiceUnavailable, "target_metadata_unavailable", "target metadata is unavailable")
			return
		}
		incarnation = marker.TargetIncarnation
	}
	if !mayStartAccountCommit(ctx, started, request.MutationBudgetMS) {
		lease.Release()
		writeAccountTimeoutV1(c)
		return
	}
	path := filepath.Join(coordinator.AuthDir(), filename)
	marker := &accountv1.Marker{Version: 1, TargetIncarnation: incarnation, BackingFilename: filename, Provider: "antigravity", NormalizedEmail: parsed.Email, ContentSHA256V1: request.ContentSHA256V1, WriteTokenV1: request.WriteTokenV1}
	marker.PostconditionProofV1, err = accountv1.EncodePostcondition(incarnation, "antigravity", parsed.Email, filename, credential, request.WriteTokenV1)
	if err != nil {
		writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "invalid postcondition input")
		return
	}
	if err = commitAccountCredentialAndMarker(coordinator, path, credential, marker, create); err != nil {
		if errors.Is(err, os.ErrExist) {
			writeAccountV1Error(c, http.StatusConflict, "auth_target_exists", "target already exists")
		} else if errors.Is(err, errAccountPhysicalCommitted) {
			h.writePartialAccountV1(c, coordinator, accountTargetInputV1{Provider: "antigravity", Email: parsed.Email, Name: filename}, lease)
		} else {
			writeAccountV1Error(c, http.StatusInternalServerError, "internal_error", "failed to commit credential")
		}
		return
	}
	auth, err := h.buildAuthFromFileData(path, credential)
	if err != nil || h.upsertAuthRecord(coreauth.WithSkipPersist(ctx), auth) != nil {
		h.writePartialAccountV1(c, coordinator, accountTargetInputV1{Provider: "antigravity", Email: parsed.Email, Name: filename}, lease)
		return
	}
	status := http.StatusOK
	if create {
		status = http.StatusCreated
	}
	response, responseOK := h.buildUploadedMutationResponseV1(coordinator, filename, parsed.Email, request.WriteTokenV1)
	if !responseOK {
		h.writePartialAccountV1(c, coordinator, accountTargetInputV1{Provider: "antigravity", Email: parsed.Email, Name: filename}, lease)
		return
	}
	lease.Release()
	c.JSON(status, response)
}

func (h *Handler) validateMutationTargetV1(c *gin.Context, coordinator *accountv1.Coordinator, input accountTargetInputV1, out *accountv1.Target) bool {
	provider, email := normalizeAccountIdentity(input.Provider, input.Email)
	if provider != "antigravity" || email == "" || input.Name == "" || input.AuthIndex == "" || accountv1.ValidateTargetPrecondition(input.TargetPreconditionV1) != nil {
		writeAccountV1Error(c, http.StatusBadRequest, "invalid_request", "invalid target")
		return false
	}
	targets, err := accountv1.ScanTargets(coordinator.AuthDir(), coordinator.Bookkeeping())
	if err != nil {
		writeAccountV1Error(c, http.StatusServiceUnavailable, "target_metadata_unavailable", "target metadata is unavailable")
		return false
	}
	h.attachAccountIndexes(targets)
	target, err := accountv1.ResolveTarget(targets, provider, email)
	if errors.Is(err, accountv1.ErrTargetNotFound) {
		writeAccountV1Error(c, http.StatusNotFound, "auth_target_not_found", "target does not exist")
		return false
	}
	if errors.Is(err, accountv1.ErrTargetAmbiguous) {
		writeAccountV1Error(c, http.StatusConflict, "auth_target_ambiguous", "multiple targets match identity")
		return false
	}
	if err != nil {
		writeAccountV1Error(c, http.StatusInternalServerError, "internal_error", "failed to resolve target")
		return false
	}
	if target.BackingFilename != input.Name || target.AuthIndex != input.AuthIndex || !accountv1.ConstantTimeEqual(target.TargetPrecondition, input.TargetPreconditionV1) {
		writeAccountV1Error(c, http.StatusConflict, "auth_target_changed", "target changed")
		return false
	}
	if out != nil {
		*out = target
	}
	return true
}

func (h *Handler) buildCurrentMutationResponseV1(coordinator *accountv1.Coordinator, input accountTargetInputV1, result string, post any) (gin.H, bool) {
	targets, err := accountv1.ScanTargets(coordinator.AuthDir(), coordinator.Bookkeeping())
	if err != nil {
		return nil, false
	}
	h.attachAccountIndexes(targets)
	target, err := accountv1.ResolveTarget(targets, input.Provider, input.Email)
	if err != nil {
		return nil, false
	}
	return gin.H{"contract_version": accountContractV1, "result": result, "quiescent": true, "target": accountTargetOutputV1{Provider: target.Provider, Email: target.Email, Name: target.BackingFilename, AuthIndex: target.AuthIndex, Disabled: target.Disabled}, "target_precondition_v1": target.TargetPrecondition, "postcondition_v1": post}, true
}
func (h *Handler) buildUploadedMutationResponseV1(coordinator *accountv1.Coordinator, filename, email, writeToken string) (gin.H, bool) {
	targets, err := accountv1.ScanTargets(coordinator.AuthDir(), coordinator.Bookkeeping())
	if err != nil {
		return nil, false
	}
	h.attachAccountIndexes(targets)
	target, err := accountv1.ResolveTarget(targets, "antigravity", email)
	if err != nil {
		return nil, false
	}
	marker, err := coordinator.Bookkeeping().Load(filename)
	if err != nil {
		return nil, false
	}
	post := accountPostconditionOutputV1{WriteTokenV1: writeToken, ContentSHA256V1: marker.ContentSHA256V1, PostconditionProofV1: marker.PostconditionProofV1}
	return gin.H{"contract_version": accountContractV1, "result": "applied", "quiescent": true, "target": accountTargetOutputV1{Provider: target.Provider, Email: target.Email, Name: filename, AuthIndex: target.AuthIndex, Disabled: target.Disabled}, "target_precondition_v1": target.TargetPrecondition, "postcondition_v1": post}, true
}
func (h *Handler) writePartialAccountV1(c *gin.Context, coordinator *accountv1.Coordinator, input accountTargetInputV1, lease *accountv1.Lease) {
	var targetPrecondition any
	var postcondition any
	if coordinator != nil {
		target, err := accountv1.RecoverTarget(coordinator.AuthDir(), input.Name, coordinator.Bookkeeping())
		if err == nil && strings.EqualFold(target.Provider, input.Provider) && strings.EqualFold(target.Email, input.Email) {
			targets := []accountv1.Target{target}
			h.attachAccountIndexes(targets)
			targetPrecondition = targets[0].TargetPrecondition
			postcondition = h.resolvedAccountV1(coordinator, targets[0])["postcondition_v1"]
		} else if errors.Is(err, accountv1.ErrTargetNotFound) {
			targetPrecondition, _ = accountv1.EncodeTargetPrecondition("absent", input.Provider, input.Email, "", "", "", nil)
		}
	}
	lease.Release()
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusInternalServerError, gin.H{
		"error":                  accountV1Error{Code: "mutation_partial", Message: "credential committed but synchronization did not complete"},
		"quiescent":              true,
		"physical_commit":        "committed",
		"target_precondition_v1": targetPrecondition,
		"postcondition_v1":       postcondition,
	})
}
func writeAccountTimeoutV1(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusGatewayTimeout, gin.H{"error": accountV1Error{Code: "mutation_timeout", Message: "account mutation timed out"}, "quiescent": true, "physical_commit": "not_started"})
}
func mayStartAccountCommit(ctx context.Context, started time.Time, mutationBudgetMS int) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	now := time.Now()
	return now.Before(started.Add(time.Duration(mutationBudgetMS)*time.Millisecond)) && started.Add(accountv1.MaxQuiescenceDuration).Sub(now) >= accountv1.MinPostCommitQuiescence
}

var errAccountUploadTooLarge = errors.New("account upload too large")
var errAccountPhysicalCommitted = errors.New("credential physical commit completed")

func accountReadTimedOut(started time.Time, err error) bool {
	var networkError net.Error
	return time.Now().After(started.Add(accountv1.MaxRequestReadDuration)) || (errors.As(err, &networkError) && networkError.Timeout())
}

func accountUploadTooLarge(err error) bool {
	var maxBytesError *http.MaxBytesError
	return errors.Is(err, errAccountUploadTooLarge) || errors.As(err, &maxBytesError)
}

func readAccountMultipartV1(c *gin.Context, started time.Time) (accountMutationInputV1, []byte, error) {
	controller := http.NewResponseController(c.Writer)
	_ = controller.SetReadDeadline(started.Add(accountv1.MaxRequestReadDuration))
	defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, accountv1.MaxAggregateUploadBytes)
	reader, err := c.Request.MultipartReader()
	if err != nil {
		return accountMutationInputV1{}, nil, err
	}
	var request accountMutationInputV1
	var credential []byte
	seen := map[string]bool{}
	for {
		part, errNext := reader.NextPart()
		if errors.Is(errNext, io.EOF) {
			break
		}
		if errNext != nil {
			return request, nil, errNext
		}
		name := part.FormName()
		if seen[name] || (name != "request" && name != "credential") {
			part.Close()
			return request, nil, errors.New("invalid multipart parts")
		}
		if part.Header.Get("Content-Type") != "application/json" || (name == "request" && part.FileName() != "") {
			part.Close()
			return request, nil, errors.New("invalid multipart part metadata")
		}
		seen[name] = true
		limited := io.LimitReader(part, accountv1.MaxCredentialBytes+1)
		raw, errRead := io.ReadAll(limited)
		part.Close()
		if errRead != nil {
			return request, nil, errRead
		}
		if name == "request" {
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if dec.Decode(&request) != nil {
				return request, nil, errors.New("invalid request part")
			}
			var extra any
			if dec.Decode(&extra) != io.EOF {
				return request, nil, errors.New("trailing request data")
			}
		} else {
			if len(raw) > accountv1.MaxCredentialBytes {
				return request, nil, errAccountUploadTooLarge
			}
			credential = raw
		}
	}
	if !seen["request"] || !seen["credential"] {
		return request, nil, errors.New("missing multipart part")
	}
	return request, credential, nil
}

func atomicWriteAccountCredential(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".relay-account-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	if err = syncAccountDirectory(dir); err != nil {
		return fmt.Errorf("%w: directory sync failed", errAccountPhysicalCommitted)
	}
	return nil
}
func syncAccountDirectory(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
func commitAccountCredentialAndMarker(coordinator *accountv1.Coordinator, path string, credential []byte, marker *accountv1.Marker, create bool) error {
	if create {
		if _, err := os.Stat(path); err == nil {
			return os.ErrExist
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	prepared, err := coordinator.Bookkeeping().Prepare(marker)
	if err != nil {
		return err
	}
	defer prepared.Abort()
	if err = atomicWriteAccountCredential(path, credential); err != nil {
		return err
	}
	if err = prepared.Commit(); err != nil {
		return fmt.Errorf("%w: marker commit failed", errAccountPhysicalCommitted)
	}
	return nil
}
