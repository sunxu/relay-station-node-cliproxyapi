package accountmanagementv1

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// DispatchFenceStore is the durable, never-garbage-collected fence set for
// remote mutation dispatch tokens. A token is represented by one file whose
// basename is the canonical lowercase UUID and whose contents are that same
// UUID. The contents make accidental or tampered path entries fail closed.
// Callers must serialize admission and fencing with Coordinator.Gate().
type DispatchFenceStore struct {
	dir string
	mu  sync.Mutex
}

func newDispatchFenceStore(authDir string) *DispatchFenceStore {
	return &DispatchFenceStore{dir: filepath.Join(authDir, SidecarDirectory, DispatchFenceDirectory)}
}

// NewDispatchFenceStore constructs a durable fence store without creating any
// directories. Creation is deferred until the first Fence call.
func NewDispatchFenceStore(authDir string) (*DispatchFenceStore, error) {
	canonical, err := canonicalAuthDir(authDir)
	if err != nil {
		return nil, err
	}
	return newDispatchFenceStore(canonical), nil
}

// Directory returns the exact on-disk dispatch-fence directory.
func (s *DispatchFenceStore) Directory() string {
	if s == nil {
		return ""
	}
	return s.dir
}

// ValidateDispatchToken accepts only the canonical lowercase UUID form used
// as the durable fence filename. UUID aliases, uppercase hex and whitespace
// are rejected so the filename identity is unambiguous.
func ValidateDispatchToken(token string) error {
	if len(token) != 36 || strings.ToLower(token) != token {
		return ErrInvalidDispatch
	}
	for i := 0; i < len(token); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if token[i] != '-' {
				return ErrInvalidDispatch
			}
			continue
		}
		c := token[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ErrInvalidDispatch
		}
	}
	return nil
}

func (s *DispatchFenceStore) fencePath(token string) string {
	return filepath.Join(s.dir, token)
}

// IsFenced reports whether token has a valid durable fence. A malformed or
// unsafe existing entry is an error and is never silently replaced.
func (s *DispatchFenceStore) IsFenced(token string) (bool, error) {
	if s == nil {
		return false, ErrDispatchMetadata
	}
	if err := ValidateDispatchToken(token); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := os.Lstat(s.fencePath(token))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: stat fence: %v", ErrDispatchMetadata, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false, fmt.Errorf("%w: unsafe fence entry", ErrDispatchMetadata)
	}
	raw, err := os.ReadFile(s.fencePath(token))
	if err != nil {
		return false, fmt.Errorf("%w: read fence: %v", ErrDispatchMetadata, err)
	}
	if string(raw) != token {
		return false, fmt.Errorf("%w: fence content mismatch", ErrDispatchMetadata)
	}
	return true, nil
}

// RequireUnfenced rejects an already durably fenced token. It is the
// admission check for a late mutation request; recovery should call Fence
// instead so the same token remains idempotently fenced.
func (s *DispatchFenceStore) RequireUnfenced(token string) error {
	fenced, err := s.IsFenced(token)
	if err != nil {
		return err
	}
	if fenced {
		return ErrDispatchFenced
	}
	return nil
}

// Fence durably records token. It is idempotent for the same valid fence and
// never removes old entries. A temp file is fsynced, linked atomically without
// replacement, then the directory is synced before success is returned.
func (s *DispatchFenceStore) Fence(token string) error {
	if s == nil {
		return ErrDispatchMetadata
	}
	if err := ValidateDispatchToken(token); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("%w: create fence directory: %v", ErrDispatchMetadata, err)
	}
	if err := os.Chmod(s.dir, 0o700); err != nil {
		return fmt.Errorf("%w: secure fence directory: %v", ErrDispatchMetadata, err)
	}
	if err := syncDirectory(filepath.Dir(s.dir)); err != nil {
		return fmt.Errorf("%w: sync fence parent directory: %v", ErrDispatchMetadata, err)
	}
	if err := syncDirectory(filepath.Dir(filepath.Dir(s.dir))); err != nil {
		return fmt.Errorf("%w: sync auth directory: %v", ErrDispatchMetadata, err)
	}
	path := s.fencePath(token)
	if fenced, err := s.isFencedLocked(token); err != nil {
		return err
	} else if fenced {
		return nil
	}

	tmp, err := os.CreateTemp(s.dir, ".relay-station-dispatch-fence-")
	if err != nil {
		return fmt.Errorf("%w: create fence: %v", ErrDispatchMetadata, err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.WriteString(token)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		cleanup()
		return fmt.Errorf("%w: write fence: %v", ErrDispatchMetadata, err)
	}
	// The AuthDir is exclusively owned by this process and Fence calls are
	// serialized by both the shared account gate and this store mutex. Publish
	// the fsynced temporary file with an atomic rename as required by the wire
	// contract, then sync the directory entry before reporting success.
	if err = os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: publish fence: %v", ErrDispatchMetadata, err)
	}
	if err = syncDirectory(s.dir); err != nil {
		return fmt.Errorf("%w: sync fence directory: %v", ErrDispatchMetadata, err)
	}
	return nil
}

func (s *DispatchFenceStore) isFencedLocked(token string) (bool, error) {
	info, err := os.Lstat(s.fencePath(token))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: stat fence: %v", ErrDispatchMetadata, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false, fmt.Errorf("%w: unsafe fence entry", ErrDispatchMetadata)
	}
	raw, err := os.ReadFile(s.fencePath(token))
	if err != nil {
		return false, fmt.Errorf("%w: read fence: %v", ErrDispatchMetadata, err)
	}
	if string(raw) != token {
		return false, fmt.Errorf("%w: fence content mismatch", ErrDispatchMetadata)
	}
	return true, nil
}

func canonicalAuthDir(authDir string) (string, error) {
	trimmed := strings.TrimSpace(authDir)
	if trimmed == "" {
		return "", fmt.Errorf("invalid auth directory")
	}
	canonical, err := filepath.Abs(filepath.Clean(trimmed))
	if err != nil || canonical == "." {
		return "", fmt.Errorf("invalid auth directory")
	}
	return canonical, nil
}
