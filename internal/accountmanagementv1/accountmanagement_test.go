package accountmanagementv1

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCoordinatorRegistryCanonicalizesAuthDir(t *testing.T) {
	dir := t.TempDir()
	a, err := ForAuthDir(filepath.Join(dir, "."))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ForAuthDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("same canonical AuthDir returned different coordinators")
	}
}

func TestGateFIFOAndCancellation(t *testing.T) {
	g := NewGate()
	first, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstReady := make(chan *Lease, 1)
	ctxSecond, cancelSecond := context.WithCancel(context.Background())
	go func() { lease, _ := g.Acquire(ctxSecond); firstReady <- lease }()
	select {
	case <-firstReady:
		t.Fatal("second ticket acquired while first held")
	case <-time.After(20 * time.Millisecond):
	}
	cancelSecond()
	if lease := <-firstReady; lease != nil {
		t.Fatal("canceled ticket acquired")
	}
	thirdReady := make(chan *Lease, 1)
	go func() {
		lease, err := g.Acquire(context.Background())
		if err != nil {
			t.Error(err)
			return
		}
		thirdReady <- lease
	}()
	first.Release()
	select {
	case third := <-thirdReady:
		third.Release()
	case <-time.After(time.Second):
		t.Fatal("third ticket did not acquire")
	}
}

func TestGateFIFOOrderAndCanceledTicketCannotOvertake(t *testing.T) {
	g := NewGate()
	first, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	secondStarted := make(chan struct{})
	secondResult := make(chan error, 1)
	secondCtx, cancelSecond := context.WithCancel(context.Background())
	go func() {
		close(secondStarted)
		lease, err := g.Acquire(secondCtx)
		if lease != nil {
			lease.Release()
		}
		secondResult <- err
	}()
	<-secondStarted
	waitForGateQueue(t, g, 1)

	thirdReady := make(chan *Lease, 1)
	go func() {
		lease, err := g.Acquire(context.Background())
		if err != nil {
			t.Errorf("third acquire: %v", err)
			return
		}
		thirdReady <- lease
	}()
	waitForGateQueue(t, g, 2)

	cancelSecond()
	if err := <-secondResult; !errors.Is(err, ErrGateCanceled) {
		t.Fatalf("second result=%v, want cancellation", err)
	}
	first.Release()

	select {
	case third := <-thirdReady:
		third.Release()
	case <-time.After(time.Second):
		t.Fatal("third ticket did not acquire after canceled ticket was removed")
	}
}

func TestHeldLeaseAvoidsSelfDeadlock(t *testing.T) {
	g := NewGate()
	outer, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithHeldLease(context.Background(), outer)
	inner, err := g.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if inner != outer {
		t.Fatal("held lease was not reused")
	}
	inner.Release()
}

func TestSidecarProvisionWriteRefreshDelete(t *testing.T) {
	dir := t.TempDir()
	b := &Bookkeeping{authDir: dir}
	name := "antigravity-user@example.com.json"
	m, err := b.Provision(name, "antigravity", "User@Example.com")
	if err != nil {
		t.Fatal(err)
	}
	if m.TargetIncarnation == "" || m.PostconditionProofV1 != "" {
		t.Fatalf("bad legacy marker: %+v", m)
	}
	if filepath.Ext(b.markerPath(name)) != "" || !strings.HasSuffix(b.markerPath(name), markerName(name)) {
		t.Fatalf("marker path must be exact lowercase hex without suffix: %s", b.markerPath(name))
	}
	if mode := fileMode(t, b.markerPath(name)); mode != 0o600 {
		t.Fatalf("marker mode %o, want 600", mode)
	}
	token, err := NewWriteToken()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"type":"antigravity","access_token":"a","refresh_token":"r"}`)
	written, err := b.RecordWrite(name, "antigravity", "user@example.com", content, token)
	if err != nil {
		t.Fatal(err)
	}
	if written.TargetIncarnation != m.TargetIncarnation || written.PostconditionProofV1 == "" {
		t.Fatalf("write marker not recorded: %+v", written)
	}
	refreshed, err := b.RecordNativeRefresh(name, []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.TargetIncarnation != m.TargetIncarnation || refreshed.PostconditionProofV1 != "" || refreshed.ContentSHA256V1 != "" {
		t.Fatalf("refresh did not invalidate proof: %+v", refreshed)
	}
	if err := b.Delete(name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(b.markerPath(name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker remains, err=%v", err)
	}
}

func TestOrphanMarkerIsNeverReusedAcrossFilenames(t *testing.T) {
	dir := t.TempDir()
	b := &Bookkeeping{authDir: dir}
	oldName := "antigravity-old@example.com.json"
	newName := "antigravity-new@example.com.json"
	raw := []byte(`{"type":"antigravity","access_token":"a","refresh_token":"r","expires_in":1,"timestamp":0,"expired":"2026-01-01T00:00:00Z","email":"new@example.com","project_id":"p"}`)

	oldMarker, err := b.Provision(oldName, "antigravity", "old@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, newName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := ScanTargets(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ResolveTarget(targets, "antigravity", "new@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.TargetIncarnation == oldMarker.TargetIncarnation {
		t.Fatal("new filename reused orphan marker incarnation")
	}
	if got.Marker == nil || got.Marker.BackingFilename != newName {
		t.Fatalf("new target marker was not bound to exact filename: %+v", got.Marker)
	}
	if _, err := os.Stat(b.markerPath(oldName)); err != nil {
		t.Fatalf("orphan marker unexpectedly disappeared: %v", err)
	}
	if got.Marker.BackingFilename == oldMarker.BackingFilename {
		t.Fatal("new target correlated with old marker filename")
	}
}

func TestSameFilenameDeleteRecreateGetsNewIncarnationAndPrecondition(t *testing.T) {
	dir := t.TempDir()
	b := &Bookkeeping{authDir: dir}
	name := "antigravity-user@example.com.json"
	raw := []byte(`{"type":"antigravity","access_token":"a","refresh_token":"r","expires_in":1,"timestamp":0,"expired":"2026-01-01T00:00:00Z","email":"user@example.com","project_id":"p"}`)
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	firstTargets, err := ScanTargets(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ResolveTarget(firstTargets, "antigravity", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(name); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	secondTargets, err := ScanTargets(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ResolveTarget(secondTargets, "antigravity", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if first.TargetIncarnation == second.TargetIncarnation {
		t.Fatal("same filename recreate reused incarnation")
	}
	if first.TargetPrecondition == second.TargetPrecondition {
		t.Fatal("same filename recreate retained old target precondition")
	}
	if err := ValidateTargetPrecondition(first.TargetPrecondition); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTargetPrecondition(second.TargetPrecondition); err != nil {
		t.Fatal(err)
	}
}

func TestTargetPreconditionStableAndChangesWithPhysicalRevision(t *testing.T) {
	content := []byte(`{"type":"antigravity","access_token":"a","refresh_token":"r"}`)
	base, err := EncodeTargetPrecondition("present", "antigravity", "User@Example.com", "incarnation-1", "antigravity-user@example.com.json", "runtime-1", content)
	if err != nil {
		t.Fatal(err)
	}
	same, err := EncodeTargetPrecondition("present", "ANTIGRAVITY", " user@example.com ", "incarnation-1", "antigravity-user@example.com.json", "runtime-1", content)
	if err != nil {
		t.Fatal(err)
	}
	if base != same {
		t.Fatal("equivalent normalized target inputs changed pt1")
	}
	variants := []struct {
		name        string
		incarnation string
		filename    string
		authIndex   string
		content     []byte
	}{
		{name: "content", incarnation: "incarnation-1", filename: "antigravity-user@example.com.json", authIndex: "runtime-1", content: []byte("changed")},
		{name: "incarnation", incarnation: "incarnation-2", filename: "antigravity-user@example.com.json", authIndex: "runtime-1", content: content},
		{name: "filename", incarnation: "incarnation-1", filename: "antigravity-other@example.com.json", authIndex: "runtime-1", content: content},
		{name: "auth index", incarnation: "incarnation-1", filename: "antigravity-user@example.com.json", authIndex: "runtime-2", content: content},
	}
	for _, variant := range variants {
		variant := variant
		t.Run(variant.name, func(t *testing.T) {
			got, err := EncodeTargetPrecondition("present", "antigravity", "user@example.com", variant.incarnation, variant.filename, variant.authIndex, variant.content)
			if err != nil {
				t.Fatal(err)
			}
			if got == base {
				t.Fatalf("pt1 did not change for %s", variant.name)
			}
		})
	}
}

func TestBackingFilenameBoundary(t *testing.T) {
	dir := t.TempDir()
	b := &Bookkeeping{authDir: dir}
	for _, tc := range []struct {
		name      string
		emailLen  int
		wantValid bool
	}{
		{name: "238-byte email", emailLen: 238, wantValid: true},
		{name: "239-byte email", emailLen: 239, wantValid: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			email := strings.Repeat("a", tc.emailLen-6) + "@b.com"
			filename := testAntigravityFilename(email)
			if len([]byte(email)) != tc.emailLen {
				t.Fatalf("email length=%d, want %d", len([]byte(email)), tc.emailLen)
			}
			if len([]byte(filename)) != tc.emailLen+17 {
				t.Fatalf("filename length=%d, want %d", len([]byte(filename)), tc.emailLen+17)
			}
			if safeBasename(filename) != tc.wantValid {
				t.Fatalf("safeBasename(%d bytes)=%v, want %v", len([]byte(filename)), safeBasename(filename), tc.wantValid)
			}
			if tc.wantValid {
				if _, err := b.Provision(filename, "antigravity", email); err != nil {
					t.Fatal(err)
				}
			} else if _, err := b.Provision(filename, "antigravity", email); !errors.Is(err, ErrTargetMetadata) {
				t.Fatalf("Provision oversized filename err=%v, want metadata rejection", err)
			}
		})
	}
}

func TestTokenEncodings(t *testing.T) {
	pt, err := EncodeTargetPrecondition("absent", "antigravity", "u@example.com", "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 47 {
		t.Fatalf("pt1 length %d", len(pt))
	}
	if err := ValidateTargetPrecondition(pt); err != nil {
		t.Fatal(err)
	}
	wt, err := NewWriteToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(wt) != 26 {
		t.Fatalf("wt1 length %d", len(wt))
	}
	if err := ValidateWriteToken(wt); err != nil {
		t.Fatal(err)
	}
	cs, _ := EncodeContentProof([]byte("credential"))
	if len(cs) != 47 {
		t.Fatalf("cs1 length %d", len(cs))
	}
	pc, err := EncodePostcondition("00000000-0000-4000-8000-000000000001", "antigravity", "u@example.com", "antigravity-u@example.com.json", []byte("credential"), wt)
	if err != nil {
		t.Fatal(err)
	}
	if len(pc) != 47 {
		t.Fatalf("pc1 length %d", len(pc))
	}
	if err := ValidatePostcondition(pc); err != nil {
		t.Fatal(err)
	}
	if !ConstantTimeEqual(pt, pt) || ConstantTimeEqual(pt, pt+"x") {
		t.Fatal("constant-time equality result incorrect")
	}
}

func TestStrictAntigravityCredentialParser(t *testing.T) {
	valid := `{"type":"antigravity","access_token":"a","refresh_token":"r","expires_in":1,"timestamp":0,"expired":"2026-01-01T00:00:00Z","email":"u@example.com","project_id":"p"}`
	if _, err := ParseAntigravityCredential([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		`{"type":"antigravity","access_token":"a","refresh_token":"r","expires_in":1,"timestamp":0,"expired":"2026-01-01T00:00:00Z","email":"u@example.com","project_id":"p","disabled":false}`,
		`{"type":"antigravity","access_token":"a","refresh_token":"r","expires_in":1,"timestamp":0,"expired":"2026-01-01T00:00:00Z","email":"u@example.com","project_id":{}}`,
		`{"type":"antigravity","access_token":"a","refresh_token":"r","expires_in":1,"timestamp":0,"expired":"2026-01-01T00:00:00Z","email":"u@example.com","project_id":"p"} trailing`,
		`{"type":"antigravity","access_token":"a","refresh_token":"r","expires_in":1,"timestamp":0,"expired":"2026-01-01T00:00:00Z","email":"u@example.com","project_id":"p","type":"antigravity"}`,
		`{"type":"antigravity","access_token":"a","refresh_token":"r","expires_in":1,"timestamp":0,"expired":"2026-01-01T00:00:00Z","email":"u@example.com","project_id":"p","nested":{"x":1}}`,
		`{"type":"antigravity","access_token":"a","refresh_token":"r","expires_in":1,"timestamp":0,"expired":"not-rfc3339","email":"u@example.com","project_id":"p"}`,
	}
	for _, raw := range cases {
		if _, err := ParseAntigravityCredential([]byte(raw)); !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("accepted invalid credential %s: %v", raw, err)
		}
	}
}

func TestScanAndResolveTargets(t *testing.T) {
	dir := t.TempDir()
	b := &Bookkeeping{authDir: dir}
	name := "antigravity-u@example.com.json"
	raw := []byte(`{"type":"antigravity","access_token":"a","refresh_token":"r","expires_in":1,"timestamp":0,"expired":"2026-01-01T00:00:00Z","email":"u@example.com","project_id":"p","disabled":true}`)
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := ScanTargetsWithAuthIndexes(dir, b, map[string]string{name: "runtime-index"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets=%d", len(targets))
	}
	got, err := ResolveTarget(targets, "ANTIGRAVITY", "U@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	if got.BackingFilename != name {
		t.Fatal(got)
	}
	if !got.Disabled || got.AuthIndex != "runtime-index" {
		t.Fatalf("durable/runtime projection missing: %+v", got)
	}
	if !strings.Contains(got.TargetPrecondition, "pt1:") {
		t.Fatal("target precondition missing")
	}
	if _, err := ResolveTarget(targets, "antigravity", "missing@example.com"); !errors.Is(err, ErrTargetNotFound) {
		t.Fatal(err)
	}
	_ = json.Valid
}

func TestScanTargetsFailsClosedForMalformedAntigravity(t *testing.T) {
	dir := t.TempDir()
	b := &Bookkeeping{authDir: dir}
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte(`{"type":"antigravity","disabled":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ScanTargets(dir, b); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("err=%v, want invalid credential", err)
	}
}

func TestScanTargetsFailsClosedForMarkerMismatch(t *testing.T) {
	dir := t.TempDir()
	b := &Bookkeeping{authDir: dir}
	name := "antigravity-u@example.com.json"
	raw := []byte(`{"type":"antigravity","access_token":"a","refresh_token":"r","expires_in":1,"timestamp":0,"expired":"2026-01-01T00:00:00Z","email":"u@example.com","project_id":"p"}`)
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Provision(name, "antigravity", "u@example.com"); err != nil {
		t.Fatal(err)
	}
	token, err := NewWriteToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.RecordWrite(name, "antigravity", "u@example.com", []byte("different"), token); err != nil {
		t.Fatal(err)
	}
	if _, err := ScanTargets(dir, b); err == nil || !errors.Is(err, ErrTargetMetadata) {
		t.Fatalf("err=%v, want metadata failure", err)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func waitForGateQueue(t *testing.T, g *Gate, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		got := len(g.queue)
		g.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("gate queue length did not reach %d", want)
}

func testAntigravityFilename(email string) string {
	return "antigravity-" + email + ".json"
}

func TestParserRejectsNonASCIIEmail(t *testing.T) {
	if validASCIIEmail("用户@example.com") {
		t.Fatal("non-ASCII email accepted")
	}
	if !strings.Contains(ErrInvalidCredential.Error(), "upload_invalid") {
		t.Fatal("unexpected error taxonomy")
	}
}
