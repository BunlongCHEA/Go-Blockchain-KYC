// Package crypto — root KEK fingerprinting and health checks.
//
// No interface changes needed — everything here is either a method on the
// existing EnvelopeEncryptor or a standalone package function.

package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// fingerprintBytes returns a short, non-reversible identifier for key
// material. Format matches generateFingerprint() in api/handlers.go
// (SHA256:<16 hex chars>) so fingerprints look consistent across the
// admin UI regardless of which kind of key they describe.
func fingerprintBytes(key []byte) string {
	sum := sha256.Sum256(key)
	return fmt.Sprintf("SHA256:%x", sum[:8]) // 8 bytes -> 16 hex chars
}

// RootKEKFingerprint returns a one-way fingerprint of the ACTIVE in-memory
// root KEK.
//
// This is the only thing that should ever be returned by an API endpoint or
// shown in an admin UI for "what is the current root KEK" — the fingerprint
// cannot be reversed to recover the key, but lets an operator visually
// confirm "yes, this matches the value in my vault" without the secret
// itself ever leaving the env var / process memory.
func (e *EnvelopeEncryptor) RootKEKFingerprint() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return fingerprintBytes(e.rootKEK)
}

// FingerprintRootKEKCandidate validates and fingerprints a CANDIDATE root key
// without storing, activating, or otherwise persisting it anywhere.
//
// Used by the /validate (dry-run) endpoint to show the operator what the new
// key's fingerprint WILL be, so they can sanity-check it before committing —
// e.g. confirm it matches what they generated client-side, or confirm two
// independently-typed copies actually match.
func FingerprintRootKEKCandidate(candidateB64 string) (fingerprint string, err error) {
	decoded, err := base64.StdEncoding.DecodeString(candidateB64)
	if err != nil {
		return "", fmt.Errorf("invalid base64")
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("must decode to exactly 32 bytes (got %d)", len(decoded))
	}
	fp := fingerprintBytes(decoded)
	zeroBytes(decoded)
	return fp, nil
}

// IsSameAsActiveRootKEK reports whether candidateB64 decodes to the SAME
// bytes as the currently active root key. Used to block no-op "rotations"
// where the new key is identical to the old one. Constant-time comparison —
// same rationale as VerifyCurrentRootKEK.
func (e *EnvelopeEncryptor) IsSameAsActiveRootKEK(candidateB64 string) bool {
	decoded, err := base64.StdEncoding.DecodeString(candidateB64)
	if err != nil || len(decoded) != 32 {
		return false
	}
	defer zeroBytes(decoded)
	e.mu.RLock()
	defer e.mu.RUnlock()
	return subtle.ConstantTimeCompare(e.rootKEK, decoded) == 1
}

// HealthCheckActiveKEK proves, end-to-end, that THIS instance's in-memory
// root key can unwrap the currently active KEK.
//
// Why this single check is sufficient evidence of full system health:
// every kyc_records.wrapped_dek and every system_keys private key is wrapped
// by the active KEK, not by the root directly. If the root can unwrap the
// active KEK, every DEK it wraps is reachable too — so this one cheap check
// (no PII touched) is a reliable proxy for "did the rotation propagate
// correctly to this replica".
//
// Deliberately bypasses the KEK cache: a cached plaintext KEK from before a
// restart would give a false "healthy" reading even if the new root can no
// longer unwrap from the database. We want proof using the CURRENT root,
// fetched fresh.
func (e *EnvelopeEncryptor) HealthCheckActiveKEK() error {
	id, err := e.ActiveKEKID()
	if err != nil {
		return fmt.Errorf("could not determine active KEK: %w", err)
	}

	e.mu.Lock()
	delete(e.kekCache, id)
	e.mu.Unlock()

	if _, err := e.unwrapKEK(id); err != nil {
		return fmt.Errorf("active KEK %s could not be unwrapped with the current root key: %w", id, err)
	}
	return nil
}
