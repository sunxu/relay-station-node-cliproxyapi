// Package accountmanagementv1 contains the Node-local primitives required by
// the Relay Station account-management contract. It deliberately has no
// dependency on the HTTP server or the runtime account manager.
package accountmanagementv1

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	SidecarDirectory        = ".relay-station-account-v1"
	DispatchFenceDirectory  = "dispatch-fences"
	MaxBackingFilenameBytes = 255
	MaxCreateEmailBytes     = 238
	MaxCredentialBytes      = 262144
	MaxAggregateUploadBytes = 270336
	MaxAccessTokenBytes     = 65536
	MaxRefreshTokenBytes    = 65536
	MaxProjectIDBytes       = 253
	MaxExpiredBytes         = 64
	MaxAuthIndexBytes       = 128
	MaxRequestReadDuration  = 5 * time.Second
	MaxMutationDuration     = 15 * time.Second
	MaxQuiescenceDuration   = 25 * time.Second
	MinPostCommitQuiescence = 10 * time.Second
	pt1Domain               = "relay-station/node-account-target-precondition/v1"
	pc1Domain               = "relay-station/node-account-postcondition/v1"
)

var (
	ErrGateCanceled      = errors.New("account mutation gate acquisition canceled")
	ErrInvalidCredential = errors.New("upload_invalid")
	ErrTargetNotFound    = errors.New("auth_target_not_found")
	ErrTargetAmbiguous   = errors.New("auth_target_ambiguous")
	ErrTargetMetadata    = errors.New("target_metadata_unavailable")
	ErrTargetChanged     = errors.New("auth_target_changed")
	ErrTargetExists      = errors.New("auth_target_exists")
	ErrInvalidDispatch   = errors.New("invalid dispatch token")
	ErrDispatchFenced    = errors.New("mutation dispatch token already fenced")
	ErrDispatchMetadata  = errors.New("dispatch fence metadata unavailable")
)

// Coordinator is the single per-AuthDir serialization and bookkeeping owner.
type Coordinator struct {
	authDir string
	gate    *Gate
	books   *Bookkeeping
	fences  *DispatchFenceStore
}

var coordinators = struct {
	sync.Mutex
	items map[string]*Coordinator
}{items: make(map[string]*Coordinator)}

// ForAuthDir returns the process-wide coordinator for one canonical AuthDir.
func ForAuthDir(authDir string) (*Coordinator, error) {
	canonical, err := filepath.Abs(filepath.Clean(strings.TrimSpace(authDir)))
	if err != nil || canonical == "." || strings.TrimSpace(authDir) == "" {
		return nil, fmt.Errorf("invalid auth directory")
	}
	coordinators.Lock()
	defer coordinators.Unlock()
	if c := coordinators.items[canonical]; c != nil {
		return c, nil
	}
	c := &Coordinator{
		authDir: canonical,
		gate:    NewGate(),
		books:   &Bookkeeping{authDir: canonical},
		fences:  newDispatchFenceStore(canonical),
	}
	coordinators.items[canonical] = c
	return c, nil
}

// LookupAuthDir returns the already-registered coordinator for authDir without
// creating one. A registered coordinator is the v1-active boundary used by
// native writers; callers that only use the legacy token store therefore do
// not opt themselves into v1 bookkeeping accidentally.
func LookupAuthDir(authDir string) (*Coordinator, bool) {
	canonical, err := filepath.Abs(filepath.Clean(strings.TrimSpace(authDir)))
	if err != nil || canonical == "." || strings.TrimSpace(authDir) == "" {
		return nil, false
	}
	coordinators.Lock()
	defer coordinators.Unlock()
	c, ok := coordinators.items[canonical]
	return c, ok
}

func (c *Coordinator) AuthDir() string {
	if c == nil {
		return ""
	}
	return c.authDir
}
func (c *Coordinator) Gate() *Gate {
	if c == nil {
		return nil
	}
	return c.gate
}
func (c *Coordinator) Bookkeeping() *Bookkeeping {
	if c == nil {
		return nil
	}
	return c.books
}

// DispatchFences returns the durable dispatch-token fence store for this
// AuthDir. Callers must hold the coordinator gate before checking or fencing a
// token so that admission and recovery ordering remain one critical section.
func (c *Coordinator) DispatchFences() *DispatchFenceStore {
	if c == nil {
		return nil
	}
	return c.fences
}

type gateTicket struct {
	ready chan struct{}
	state gateTicketState
	lease *Lease
}

type gateTicketState uint8

const (
	ticketQueued gateTicketState = iota
	ticketGranted
	ticketCanceled
)

// Gate is a FIFO, cancelable, non-reentrant mutation gate.
type Gate struct {
	mu    sync.Mutex
	queue []*gateTicket
	held  bool
}

func NewGate() *Gate { return &Gate{} }

// Lease is held until Release. A lease can be carried in a context to prevent
// nested bookkeeping calls from self-deadlocking.
type Lease struct {
	gate     *Gate
	released atomic.Bool
}
type heldKey struct{}

func WithHeldLease(ctx context.Context, lease *Lease) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, heldKey{}, lease)
}

func HeldLease(ctx context.Context) *Lease {
	if ctx == nil {
		return nil
	}
	lease, _ := ctx.Value(heldKey{}).(*Lease)
	if lease == nil || lease.released.Load() {
		return nil
	}
	return lease
}

func heldLeaseFor(g *Gate, ctx context.Context) *Lease {
	lease := HeldLease(ctx)
	if lease == nil || lease.gate != g {
		return nil
	}
	return lease
}

// Acquire appends before waiting, so a later resolve cannot overtake an
// admitted mutation. A canceled ticket is removed and can never acquire later.
func (g *Gate) Acquire(ctx context.Context) (*Lease, error) {
	if g == nil {
		return nil, fmt.Errorf("nil mutation gate")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGateCanceled, err)
	}
	if lease := heldLeaseFor(g, ctx); lease != nil {
		return lease, nil
	}
	t := &gateTicket{ready: make(chan struct{}), state: ticketQueued}
	g.mu.Lock()
	g.queue = append(g.queue, t)
	g.promoteLocked()
	g.mu.Unlock()
	select {
	case <-t.ready:
		g.mu.Lock()
		lease := t.lease
		state := t.state
		g.mu.Unlock()
		if state != ticketGranted || lease == nil {
			return nil, fmt.Errorf("mutation gate granted without lease")
		}
		return lease, nil
	case <-ctx.Done():
		g.mu.Lock()
		switch t.state {
		case ticketQueued:
			t.state = ticketCanceled
			for i, queued := range g.queue {
				if queued == t {
					g.queue = append(g.queue[:i], g.queue[i+1:]...)
					break
				}
			}
			g.promoteLocked()
			g.mu.Unlock()
			return nil, fmt.Errorf("%w: %v", ErrGateCanceled, ctx.Err())
		case ticketGranted:
			// A grant that won the mutex race owns the gate even if the
			// context became done before the select observed ready. Return
			// that lease so the caller can release it; never strand held=true.
			lease := t.lease
			g.mu.Unlock()
			return lease, nil
		default:
			g.mu.Unlock()
			return nil, fmt.Errorf("%w: %v", ErrGateCanceled, ctx.Err())
		}
	}
}

func (g *Gate) promoteLocked() {
	for !g.held && len(g.queue) > 0 {
		t := g.queue[0]
		g.queue = g.queue[1:]
		if t.state == ticketCanceled {
			continue
		}
		t.state = ticketGranted
		t.lease = &Lease{gate: g}
		g.held = true
		close(t.ready)
	}
}

func (l *Lease) Release() {
	if l == nil || l.gate == nil || l.released.Swap(true) {
		return
	}
	g := l.gate
	g.mu.Lock()
	g.held = false
	g.promoteLocked()
	g.mu.Unlock()
}

// Marker is the non-secret sidecar record for one exact backing filename.
type Marker struct {
	Version              int    `json:"version"`
	TargetIncarnation    string `json:"target_incarnation"`
	BackingFilename      string `json:"backing_filename"`
	Provider             string `json:"provider"`
	NormalizedEmail      string `json:"normalized_email"`
	ContentSHA256V1      string `json:"content_sha256_v1"`
	WriteTokenV1         string `json:"write_token_v1"`
	PostconditionProofV1 string `json:"postcondition_proof_v1"`
}

// MarshalJSON preserves the frozen null representation for an absent
// Create/Replace postcondition on provisioned and natively updated targets.
func (m Marker) MarshalJSON() ([]byte, error) {
	type markerJSON struct {
		Version              int     `json:"version"`
		TargetIncarnation    string  `json:"target_incarnation"`
		BackingFilename      string  `json:"backing_filename"`
		Provider             string  `json:"provider"`
		NormalizedEmail      string  `json:"normalized_email"`
		ContentSHA256V1      *string `json:"content_sha256_v1"`
		WriteTokenV1         *string `json:"write_token_v1"`
		PostconditionProofV1 *string `json:"postcondition_proof_v1"`
	}
	optional := func(value string) *string {
		if value == "" {
			return nil
		}
		return &value
	}
	return json.Marshal(markerJSON{
		Version: m.Version, TargetIncarnation: m.TargetIncarnation,
		BackingFilename: m.BackingFilename, Provider: m.Provider,
		NormalizedEmail: m.NormalizedEmail, ContentSHA256V1: optional(m.ContentSHA256V1),
		WriteTokenV1: optional(m.WriteTokenV1), PostconditionProofV1: optional(m.PostconditionProofV1),
	})
}

// Bookkeeping owns exact-filename marker operations. Callers must hold the
// coordinator gate when combining these operations with credential writes.
type Bookkeeping struct{ authDir string }

func (b *Bookkeeping) sidecarDir() string { return filepath.Join(b.authDir, SidecarDirectory) }
func markerName(filename string) string {
	sum := sha256.Sum256([]byte(filename))
	return hex.EncodeToString(sum[:])
}
func (b *Bookkeeping) markerPath(filename string) string {
	return filepath.Join(b.sidecarDir(), markerName(filename))
}

func (b *Bookkeeping) Load(filename string) (*Marker, error) {
	if b == nil || !safeBasename(filename) {
		return nil, ErrTargetMetadata
	}
	raw, err := os.ReadFile(b.markerPath(filename))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("load marker: %w", err)
	}
	var m Marker
	if json.Unmarshal(raw, &m) != nil || m.Version != 1 || m.BackingFilename != filename || m.TargetIncarnation == "" {
		return nil, ErrTargetMetadata
	}
	return &m, nil
}

func (b *Bookkeeping) Provision(filename, provider, email string) (*Marker, error) {
	if b == nil || !safeBasename(filename) {
		return nil, ErrTargetMetadata
	}
	if existing, err := b.Load(filename); err == nil {
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	inc, err := NewIncarnation()
	if err != nil {
		return nil, err
	}
	m := &Marker{Version: 1, TargetIncarnation: inc, BackingFilename: filename, Provider: strings.ToLower(strings.TrimSpace(provider)), NormalizedEmail: normalizeEmail(email)}
	return m, b.save(m)
}

func (b *Bookkeeping) RecordWrite(filename, provider, email string, content []byte, writeToken string) (*Marker, error) {
	if err := ValidateWriteToken(writeToken); err != nil {
		return nil, err
	}
	m, err := b.Load(filename)
	if errors.Is(err, os.ErrNotExist) {
		m, err = b.Provision(filename, provider, email)
	}
	if err != nil {
		return nil, err
	}
	contentDigest, err := EncodeContentProof(content)
	if err != nil {
		return nil, err
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	email = normalizeEmail(email)
	if m.Provider != provider || m.NormalizedEmail != email {
		return nil, fmt.Errorf("%w: marker identity mismatch", ErrTargetMetadata)
	}
	m.Provider, m.NormalizedEmail = provider, email
	m.ContentSHA256V1, m.WriteTokenV1 = contentDigest, writeToken
	m.PostconditionProofV1, err = EncodePostcondition(m.TargetIncarnation, m.Provider, m.NormalizedEmail, filename, content, writeToken)
	if err != nil {
		return nil, err
	}
	return m, b.save(m)
}

// RecordNativeRefresh preserves incarnation but invalidates prior operation proof.
func (b *Bookkeeping) RecordNativeRefresh(filename string, content []byte) (*Marker, error) {
	m, err := b.Load(filename)
	if err != nil {
		return nil, err
	}
	m.ContentSHA256V1, m.WriteTokenV1, m.PostconditionProofV1 = "", "", ""
	if _, err = EncodeContentProof(content); err != nil {
		return nil, err
	}
	return m, b.save(m)
}

func (b *Bookkeeping) Delete(filename string) error {
	if b == nil || !safeBasename(filename) {
		return ErrTargetMetadata
	}
	err := os.Remove(b.markerPath(filename))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDirectory(b.sidecarDir())
}

func (b *Bookkeeping) save(m *Marker) error {
	if err := os.MkdirAll(b.sidecarDir(), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return atomicWrite(b.markerPath(m.BackingFilename), raw, 0o600)
}

// PreparedMarker is a durable temporary marker waiting for the credential
// physical commit. Commit publishes it atomically; Abort removes the temp.
type PreparedMarker struct {
	temporary string
	final     string
}

func (b *Bookkeeping) Prepare(m *Marker) (*PreparedMarker, error) {
	if b == nil || m == nil || !safeBasename(m.BackingFilename) {
		return nil, ErrTargetMetadata
	}
	if err := os.MkdirAll(b.sidecarDir(), 0o700); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(b.sidecarDir(), ".relay-station-marker-")
	if err != nil {
		return nil, err
	}
	name := tmp.Name()
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(raw)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(name)
		return nil, err
	}
	return &PreparedMarker{temporary: name, final: b.markerPath(m.BackingFilename)}, nil
}

func (p *PreparedMarker) Commit() error {
	if p == nil || p.temporary == "" || p.final == "" {
		return ErrTargetMetadata
	}
	if err := os.Rename(p.temporary, p.final); err != nil {
		return err
	}
	p.temporary = ""
	return syncDirectory(filepath.Dir(p.final))
}

func (p *PreparedMarker) Abort() {
	if p != nil && p.temporary != "" {
		_ = os.Remove(p.temporary)
		p.temporary = ""
	}
}

func NewIncarnation() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func safeBasename(name string) bool {
	return name != "" && filepath.Base(name) == name && !strings.ContainsAny(name, `/\\`) && len([]byte(name)) <= MaxBackingFilenameBytes
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".relay-station-tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(mode); err == nil {
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
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Target is a sanitized physical target projection. Raw credential bytes are not retained.
type Target struct {
	Provider           string
	Email              string
	BackingFilename    string
	AuthIndex          string
	Disabled           bool
	TargetIncarnation  string
	TargetPrecondition string
	Marker             *Marker
}

// ScanTargets reads only Antigravity JSON files and returns sanitized targets.
func ScanTargets(authDir string, books *Bookkeeping) ([]Target, error) {
	return ScanTargetsWithAuthIndexes(authDir, books, nil)
}

// RecoverTarget reads one exact physical target after a known credential
// commit. Unlike the normal scanner it tolerates a stale postcondition marker
// so callers can return the current pt1 while withholding an invalid proof.
// Callers must hold the account mutation gate.
func RecoverTarget(authDir, filename string, books *Bookkeeping) (Target, error) {
	if books == nil || !safeBasename(filename) {
		return Target{}, ErrTargetMetadata
	}
	raw, err := os.ReadFile(filepath.Join(authDir, filename))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Target{}, ErrTargetNotFound
		}
		return Target{}, err
	}
	provider, ok := storedProvider(raw)
	if !ok || provider != "antigravity" {
		return Target{}, ErrInvalidCredential
	}
	credential, err := parseStoredAntigravityCredential(raw)
	if err != nil {
		return Target{}, err
	}
	marker, err := books.Load(filename)
	if errors.Is(err, os.ErrNotExist) {
		marker, err = books.Provision(filename, provider, credential.Email)
	}
	if err != nil || marker.Provider != provider || marker.NormalizedEmail != credential.Email {
		return Target{}, ErrTargetMetadata
	}
	precondition, err := EncodeTargetPrecondition("present", provider, credential.Email, marker.TargetIncarnation, filename, "", raw)
	if err != nil {
		return Target{}, err
	}
	return Target{Provider: provider, Email: credential.Email, BackingFilename: filename, Disabled: credential.Disabled, TargetIncarnation: marker.TargetIncarnation, TargetPrecondition: precondition, Marker: marker}, nil
}

// ScanTargetsWithAuthIndexes is ScanTargets with caller-supplied runtime
// auth_index values. The values are keyed by exact backing filename and are
// included in the target precondition without being read from credential JSON.
func ScanTargetsWithAuthIndexes(authDir string, books *Bookkeeping, authIndexes map[string]string) ([]Target, error) {
	entries, err := os.ReadDir(authDir)
	if err != nil {
		return nil, err
	}
	var out []Target
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		path := filepath.Join(authDir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		provider, providerOK := storedProvider(raw)
		if !providerOK {
			if strings.HasPrefix(strings.ToLower(e.Name()), "antigravity-") || strings.EqualFold(e.Name(), "antigravity.json") {
				return nil, fmt.Errorf("%w: malformed Antigravity target %s", ErrInvalidCredential, e.Name())
			}
			continue
		}
		if provider != "antigravity" {
			continue
		}
		cred, err := parseStoredAntigravityCredential(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalidCredential, e.Name(), err)
		}
		m, err := books.Load(e.Name())
		if errors.Is(err, os.ErrNotExist) {
			m, err = books.Provision(e.Name(), "antigravity", cred.Email)
		}
		if err != nil {
			return nil, err
		}
		if m.Provider != "antigravity" || m.NormalizedEmail != cred.Email {
			return nil, fmt.Errorf("%w: marker identity mismatch for %s", ErrTargetMetadata, e.Name())
		}
		if m.ContentSHA256V1 != "" {
			currentContent, errDigest := EncodeContentProof(raw)
			if errDigest != nil || !ConstantTimeEqual(currentContent, m.ContentSHA256V1) {
				return nil, fmt.Errorf("%w: marker content mismatch for %s", ErrTargetMetadata, e.Name())
			}
		}
		authIndex := ""
		if authIndexes != nil {
			authIndex = strings.TrimSpace(authIndexes[e.Name()])
			if len([]byte(authIndex)) > MaxAuthIndexBytes || !isASCII(authIndex) {
				return nil, fmt.Errorf("%w: invalid auth_index for %s", ErrTargetMetadata, e.Name())
			}
		}
		pt, err := EncodeTargetPrecondition("present", "antigravity", cred.Email, m.TargetIncarnation, e.Name(), authIndex, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, Target{Provider: "antigravity", Email: cred.Email, BackingFilename: e.Name(), AuthIndex: authIndex, Disabled: cred.Disabled, TargetIncarnation: m.TargetIncarnation, TargetPrecondition: pt, Marker: m})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BackingFilename < out[j].BackingFilename })
	return out, nil
}

func storedProvider(raw []byte) (string, bool) {
	var value struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(value.Type)), strings.TrimSpace(value.Type) != ""
}

// parseStoredAntigravityCredential accepts the one runtime field that is
// already durable in existing files. The upload parser remains strict and
// rejects it; this path is only for reading an existing runtime projection.
func parseStoredAntigravityCredential(raw []byte) (*AntigravityCredential, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return nil, ErrInvalidCredential
	}
	disabled := false
	if value, ok := object["disabled"]; ok {
		if json.Unmarshal(value, &disabled) != nil {
			return nil, ErrInvalidCredential
		}
		delete(object, "disabled")
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return nil, ErrInvalidCredential
	}
	cred, err := ParseAntigravityCredential(canonical)
	if err != nil {
		return nil, err
	}
	cred.Disabled = disabled
	return cred, nil
}

func ResolveTarget(targets []Target, provider, email string) (Target, error) {
	provider, email = strings.ToLower(strings.TrimSpace(provider)), normalizeEmail(email)
	var matches []Target
	for _, t := range targets {
		if t.Provider == provider && t.Email == email {
			matches = append(matches, t)
		}
	}
	if len(matches) == 0 {
		return Target{}, ErrTargetNotFound
	}
	if len(matches) > 1 {
		return Target{}, ErrTargetAmbiguous
	}
	return matches[0], nil
}

type AntigravityCredential struct {
	Type         string
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	Timestamp    int64
	Expired      string
	Email        string
	ProjectID    string
	Disabled     bool
}

var credentialFields = map[string]bool{"type": true, "access_token": true, "refresh_token": true, "expires_in": true, "timestamp": true, "expired": true, "email": true, "project_id": true}

// ParseAntigravityCredential strictly accepts the frozen top-level schema.
func ParseAntigravityCredential(raw []byte) (*AntigravityCredential, error) {
	if len(raw) == 0 || len(raw) > MaxCredentialBytes {
		return nil, ErrInvalidCredential
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, ErrInvalidCredential
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, ErrInvalidCredential
	}
	values := make(map[string]json.RawMessage)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, ErrInvalidCredential
		}
		key, ok := keyTok.(string)
		if !ok || !credentialFields[key] {
			return nil, ErrInvalidCredential
		}
		if _, exists := values[key]; exists {
			return nil, ErrInvalidCredential
		}
		var value json.RawMessage
		if err = dec.Decode(&value); err != nil {
			return nil, ErrInvalidCredential
		}
		values[key] = value
	}
	if _, err = dec.Token(); err != nil {
		return nil, ErrInvalidCredential
	}
	if dec.More() {
		return nil, ErrInvalidCredential
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return nil, ErrInvalidCredential
	}
	var c AntigravityCredential
	if !stringValue(values, "type", &c.Type) || c.Type != "antigravity" || !stringValue(values, "access_token", &c.AccessToken) || !stringValue(values, "refresh_token", &c.RefreshToken) || !stringValue(values, "expired", &c.Expired) || !stringValue(values, "email", &c.Email) || !stringValue(values, "project_id", &c.ProjectID) {
		return nil, ErrInvalidCredential
	}
	if len(c.AccessToken) > MaxAccessTokenBytes || len(c.RefreshToken) > MaxRefreshTokenBytes || len(c.Expired) > MaxExpiredBytes || len(c.ProjectID) > MaxProjectIDBytes || !validASCIIEmail(c.Email) {
		return nil, ErrInvalidCredential
	}
	if _, err := time.Parse(time.RFC3339, c.Expired); err != nil {
		return nil, ErrInvalidCredential
	}
	if !intValue(values, "expires_in", &c.ExpiresIn) || c.ExpiresIn < 0 || c.ExpiresIn > 315360000 || !intValue(values, "timestamp", &c.Timestamp) || c.Timestamp < 0 || c.Timestamp > 253402300799999 {
		return nil, ErrInvalidCredential
	}
	c.Email = normalizeEmail(c.Email)
	return &c, nil
}

func stringValue(values map[string]json.RawMessage, key string, out *string) bool {
	raw, ok := values[key]
	if !ok || json.Unmarshal(raw, out) != nil || *out == "" {
		return false
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	_, ok = v.(string)
	return ok
}
func intValue(values map[string]json.RawMessage, key string, out *int64) bool {
	raw, ok := values[key]
	if !ok {
		return false
	}
	var n json.Number
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if d.Decode(&n) != nil {
		return false
	}
	v, err := n.Int64()
	if err != nil {
		return false
	}
	*out = v
	return true
}
func validASCIIEmail(value string) bool {
	if len(value) > 320 || strings.IndexFunc(value, func(r rune) bool { return r > 127 || r < 32 }) >= 0 {
		return false
	}
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value && strings.Count(value, "@") == 1
}

func isASCII(value string) bool {
	for _, r := range value {
		if r > 127 || r < 32 {
			return false
		}
	}
	return true
}
func normalizeEmail(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func fieldBytes(dst []byte, value []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(value)))
	dst = append(dst, n[:]...)
	return append(dst, value...)
}
func digestToken(prefix string, digest []byte) string {
	return prefix + base64.RawURLEncoding.EncodeToString(digest)
}
func decodeToken(token, prefix string, length int) ([]byte, error) {
	if !strings.HasPrefix(token, prefix) {
		return nil, fmt.Errorf("invalid token")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, prefix))
	if err != nil || len(b) != length || base64.RawURLEncoding.EncodeToString(b) != strings.TrimPrefix(token, prefix) {
		return nil, fmt.Errorf("invalid token")
	}
	return b, nil
}

func EncodeTargetPrecondition(state, provider, email, incarnation, filename, authIndex string, content []byte) (string, error) {
	canonical, err := canonicalTargetPrecondition(state, provider, email, incarnation, filename, authIndex, content)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return digestToken("pt1:", sum[:]), nil
}

func canonicalTargetPrecondition(state, provider, email, incarnation, filename, authIndex string, content []byte) ([]byte, error) {
	var contentDigest []byte
	if state == "present" {
		sum := sha256.Sum256(content)
		contentDigest = sum[:]
		if !safeBasename(filename) {
			return nil, ErrTargetMetadata
		}
	} else if state != "absent" {
		return nil, fmt.Errorf("invalid target state")
	}
	canonical := append([]byte(nil), []byte(pt1Domain)...)
	for _, v := range []string{state, strings.ToLower(strings.TrimSpace(provider)), normalizeEmail(email), incarnation, filename, authIndex} {
		canonical = fieldBytes(canonical, []byte(v))
	}
	canonical = fieldBytes(canonical, contentDigest)
	return canonical, nil
}
func ValidateTargetPrecondition(token string) error {
	b, err := decodeToken(token, "pt1:", 32)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("invalid pt1")
	}
	return nil
}
func EncodeWriteToken(raw []byte) (string, error) {
	if len(raw) != 16 {
		return "", fmt.Errorf("write token must contain 16 bytes")
	}
	return digestToken("wt1:", raw), nil
}
func NewWriteToken() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return EncodeWriteToken(b)
}
func ValidateWriteToken(token string) error { _, err := decodeToken(token, "wt1:", 16); return err }
func EncodeContentProof(raw []byte) (string, error) {
	sum := sha256.Sum256(raw)
	return digestToken("cs1:", sum[:]), nil
}
func ValidateContentProof(token string) error { _, err := decodeToken(token, "cs1:", 32); return err }
func EncodePostcondition(incarnation, provider, email, filename string, content []byte, writeToken string) (string, error) {
	canonical, err := canonicalPostcondition(incarnation, provider, email, filename, content, writeToken)
	if err != nil {
		return "", err
	}
	proof := sha256.Sum256(canonical)
	return digestToken("pc1:", proof[:]), nil
}

func canonicalPostcondition(incarnation, provider, email, filename string, content []byte, writeToken string) ([]byte, error) {
	wt, err := decodeToken(writeToken, "wt1:", 16)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	canonical := append([]byte(nil), []byte(pc1Domain)...)
	for _, v := range []string{incarnation, strings.ToLower(strings.TrimSpace(provider)), normalizeEmail(email), filename} {
		canonical = fieldBytes(canonical, []byte(v))
	}
	canonical = fieldBytes(canonical, sum[:])
	canonical = fieldBytes(canonical, wt)
	return canonical, nil
}
func ValidatePostcondition(token string) error { _, err := decodeToken(token, "pc1:", 32); return err }

// ConstantTimeEqual compares canonical token strings without an early secret-dependent comparison.
func ConstantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
