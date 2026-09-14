package accountmanagementv1

import (
	"context"
	"encoding/hex"
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

func TestHeldLeaseOnlyReusesTheSameGate(t *testing.T) {
	firstGate := NewGate()
	secondGate := NewGate()
	outer, err := firstGate.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Release()
	ctx := WithHeldLease(context.Background(), outer)

	inner, err := secondGate.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if inner == outer {
		t.Fatal("held lease from another gate was reused")
	}
	inner.Release()
}

func TestGateGrantCancellationRaceDoesNotStrandGate(t *testing.T) {
	const iterations = 1200
	for i := 0; i < iterations; i++ {
		g := NewGate()
		holder, err := g.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan struct {
			lease *Lease
			err   error
		}, 1)
		go func() {
			lease, acquireErr := g.Acquire(ctx)
			result <- struct {
				lease *Lease
				err   error
			}{lease: lease, err: acquireErr}
		}()
		waitForGateQueue(t, g, 1)

		start := make(chan struct{})
		go func() {
			<-start
			holder.Release()
		}()
		go func() {
			<-start
			cancel()
		}()
		close(start)

		r := <-result
		if r.err != nil && !errors.Is(r.err, ErrGateCanceled) {
			t.Fatalf("iteration %d: acquire err=%v", i, r.err)
		}
		if r.lease != nil {
			r.lease.Release()
		}

		probeCtx, probeCancel := context.WithTimeout(context.Background(), time.Second)
		probe, probeErr := g.Acquire(probeCtx)
		probeCancel()
		if probeErr != nil {
			t.Fatalf("iteration %d: gate stranded: %v", i, probeErr)
		}
		probe.Release()
	}
}

func TestGateRejectsPreCanceledContext(t *testing.T) {
	g := NewGate()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if lease, err := g.Acquire(ctx); lease != nil || !errors.Is(err, ErrGateCanceled) {
		t.Fatalf("pre-canceled acquire lease=%v err=%v", lease, err)
	}
}

func TestDispatchFenceDurableAcrossStoreRestartAndNeverGCs(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDispatchFenceStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	first := "01234567-89ab-4cde-8fab-0123456789ab"
	second := "fedcba98-7654-4321-8fed-cba987654321"
	if fenced, err := store.IsFenced(first); err != nil || fenced {
		t.Fatalf("new token fenced=%v err=%v", fenced, err)
	}
	if err := store.Fence(first); err != nil {
		t.Fatal(err)
	}
	if err := store.Fence(first); err != nil {
		t.Fatalf("idempotent fence: %v", err)
	}
	if err := store.Fence(second); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewDispatchFenceStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info, statErr := os.Stat(restarted.Directory()); statErr != nil {
		t.Fatal(statErr)
	} else if info.Mode().Perm() != 0o700 {
		t.Fatalf("fence directory mode=%o, want 700", info.Mode().Perm())
	}
	for _, token := range []string{first, second} {
		fenced, fenceErr := restarted.IsFenced(token)
		if fenceErr != nil || !fenced {
			t.Fatalf("token %s after restart fenced=%v err=%v", token, fenced, fenceErr)
		}
		info, statErr := os.Stat(filepath.Join(restarted.Directory(), token))
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("token %s mode=%o, want 600", token, info.Mode().Perm())
		}
		raw, readErr := os.ReadFile(filepath.Join(restarted.Directory(), token))
		if readErr != nil || string(raw) != token {
			t.Fatalf("token %s content=%q err=%v", token, raw, readErr)
		}
	}
	if err := restarted.RequireUnfenced(first); !errors.Is(err, ErrDispatchFenced) {
		t.Fatalf("fenced admission err=%v, want ErrDispatchFenced", err)
	}
	if err := restarted.RequireUnfenced("01234567-89ab-4cde-8fab-0123456789ac"); err != nil {
		t.Fatalf("unfenced admission: %v", err)
	}
	entries, err := os.ReadDir(restarted.Directory())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("fence count=%d, want 2 without GC", len(entries))
	}
	for _, invalid := range []string{"01234567-89AB-4cde-8fab-0123456789ab", "0123456789abcdef0123456789abcdef0123"} {
		if err := restarted.Fence(invalid); !errors.Is(err, ErrInvalidDispatch) {
			t.Fatalf("invalid token %q err=%v", invalid, err)
		}
	}
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

func TestTargetAndPostconditionGoldenVectors(t *testing.T) {
	const (
		absentCanonical  = "72656c61792d73746174696f6e2f6e6f64652d6163636f756e742d7461726765742d707265636f6e646974696f6e2f763100000006616273656e740000000b616e7469677261766974790000000d75406578616d706c652e636f6d00000000000000000000000000000000"
		absentToken      = "pt1:yjr-kivbnszxEXRk151SlZyfKAzDmrJAqsGL0d3CSrA"
		presentCanonical = "72656c61792d73746174696f6e2f6e6f64652d6163636f756e742d7461726765742d707265636f6e646974696f6e2f76310000000770726573656e740000000b616e7469677261766974790000000d75406578616d706c652e636f6d0000002430303030303030302d303030302d343030302d383030302d3030303030303030303030310000001e616e7469677261766974792d75406578616d706c652e636f6d2e6a736f6e0000000972756e74696d652d3100000020e265b6f564601a1fe8dc42785cd18a868bd8013eb5899560e79248767a683e6b"
		presentToken     = "pt1:sr-6kxyu4M13TNW-Arj2HEh3vZ2qeWKyAiE4lfAcEMA"
		pcCanonical      = "72656c61792d73746174696f6e2f6e6f64652d6163636f756e742d706f7374636f6e646974696f6e2f76310000002430303030303030302d303030302d343030302d383030302d3030303030303030303030310000000b616e7469677261766974790000000d75406578616d706c652e636f6d0000001e616e7469677261766974792d75406578616d706c652e636f6d2e6a736f6e00000020e265b6f564601a1fe8dc42785cd18a868bd8013eb5899560e79248767a683e6b00000010000102030405060708090a0b0c0d0e0f"
		pcToken          = "pc1:36l9PpOU6K8EBm2eLzpvWG60UmovVwxm_baDBp2XWmU"
		incarnation      = "00000000-0000-4000-8000-000000000001"
		filename         = "antigravity-u@example.com.json"
		writeToken       = "wt1:AAECAwQFBgcICQoLDA0ODw"
	)

	absent, err := canonicalTargetPrecondition("absent", "antigravity", "u@example.com", "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(absent); got != absentCanonical {
		t.Fatalf("absent canonical=%s", got)
	}
	absentEncoded, err := EncodeTargetPrecondition("absent", "antigravity", "u@example.com", "", "", "", nil)
	if err != nil || absentEncoded != absentToken {
		t.Fatalf("absent token=%s err=%v", absentEncoded, err)
	}

	present, err := canonicalTargetPrecondition("present", "antigravity", "u@example.com", incarnation, filename, "runtime-1", []byte("credential"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(present); got != presentCanonical {
		t.Fatalf("present canonical=%s", got)
	}
	presentEncoded, err := EncodeTargetPrecondition("present", "antigravity", "u@example.com", incarnation, filename, "runtime-1", []byte("credential"))
	if err != nil || presentEncoded != presentToken {
		t.Fatalf("present token=%s err=%v", presentEncoded, err)
	}

	pc, err := canonicalPostcondition(incarnation, "antigravity", "u@example.com", filename, []byte("credential"), writeToken)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pc); got != pcCanonical {
		t.Fatalf("pc canonical=%s", got)
	}
	pcEncoded, err := EncodePostcondition(incarnation, "antigravity", "u@example.com", filename, []byte("credential"), writeToken)
	if err != nil || pcEncoded != pcToken {
		t.Fatalf("pc token=%s err=%v", pcEncoded, err)
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
