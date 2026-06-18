package crypto

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// VerifyCurrentRootKEK reports whether rootKEKB64 matches the active
// in-memory root key. Uses constant-time comparison to prevent
// timing side-channel attacks.
//
// Called by the RotateRootKEK API handler as a proof-of-knowledge gate
// before accepting a new root key.
func (e *EnvelopeEncryptor) VerifyCurrentRootKEK(rootKEKB64 string) bool {
	decoded, err := base64.StdEncoding.DecodeString(rootKEKB64)
	if err != nil || len(decoded) != 32 {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return subtle.ConstantTimeCompare(e.rootKEK, decoded) == 1
}

// RotateRootKEK re-wraps every KEK stored in kek_keys under newRootKEKB64,
// then atomically updates the in-memory root key on this server instance.
//
// CALL WHILE THE SERVER IS RUNNING WITH THE CURRENT ROOT KEY — it must be
// able to decrypt the existing wrapped_key values before re-wrapping them.
//
// After this returns successfully:
//
//  1. Every kek_keys.wrapped_key column is encrypted under the new root.
//  2. This instance's in-memory rootKEK is updated immediately.
//  3. The caller must set KYC_ROOT_KEK=<newRootKEKB64> in the environment
//     and restart all other replicas so they boot with the new key.
//
// # Why only kek_keys rows are touched
//
// The key hierarchy is:
//
//	Root KEK (env)
//	  └─ wraps → KEK (kek_keys.wrapped_key)
//	               └─ wraps → DEK (kyc_records.wrapped_dek)
//	                            └─ encrypts → PII ciphertext
//	               └─ wraps → signing-key DEK (system_keys, via EncryptField)
//
// DEKs are wrapped by the KEK — not by the root directly. Re-wrapping the KEK
// rows under the new root restores access to the entire hierarchy without
// touching kyc_records or system_keys.
//
// If the DB write fails the transaction is rolled back — the old root remains
// valid, no data loss occurs.
//
// Returns the number of KEK rows that were re-wrapped.
func (e *EnvelopeEncryptor) RotateRootKEK(newRootKEKB64 string) (int, error) {
	// ── Validate the new root key ─────────────────────────────────────────────
	newRoot, err := base64.StdEncoding.DecodeString(newRootKEKB64)
	if err != nil {
		return 0, fmt.Errorf("new root KEK: invalid base64: %w", err)
	}
	if len(newRoot) != 32 {
		return 0, fmt.Errorf("new root KEK must decode to 32 bytes (got %d)", len(newRoot))
	}

	// ── Snapshot the current root under a read lock ───────────────────────────
	// Copy so the loop can run without holding the lock.
	e.mu.RLock()
	currentRoot := make([]byte, 32)
	copy(currentRoot, e.rootKEK)
	e.mu.RUnlock()
	// Zero both copies on any return path.
	defer zeroBytes(currentRoot)

	// ── List all KEK records ──────────────────────────────────────────────────
	records, err := e.store.ListKEKs()
	if err != nil {
		zeroBytes(newRoot)
		return 0, fmt.Errorf("list KEKs: %w", err)
	}
	if len(records) == 0 {
		zeroBytes(newRoot)
		return 0, fmt.Errorf("no KEK records found — has the database been bootstrapped?")
	}

	// ── Re-wrap each KEK under the new root ───────────────────────────────────
	//
	// For every kek_keys row:
	//   1. Fetch wrapped_key from the store (the AES-GCM blob)
	//   2. aesGCMDecrypt(currentRoot, wrappedKey) → plainKEK  (32-byte KEK)
	//   3. aesGCMEncrypt(newRoot,     plainKEK)   → newWrapped
	//   4. Accumulate in the updates map; plainKEK is zeroed immediately.
	//
	// Nothing is written to the DB yet — we want all re-wraps to succeed
	// before committing.
	updates := make(map[string]string, len(records))

	for _, rec := range records {
		wrappedKey, _, err := e.store.GetKEK(rec.KEKID)
		if err != nil {
			zeroBytes(newRoot)
			return 0, fmt.Errorf("fetch KEK %s: %w", rec.KEKID, err)
		}

		// Decrypt with the current root.
		// An authentication failure here means the in-memory root no longer
		// matches the DB — e.g. the env var was hot-swapped on this replica
		// without going through the rotation endpoint.
		plainKEK, err := aesGCMDecrypt(currentRoot, wrappedKey)
		if err != nil {
			zeroBytes(newRoot)
			return 0, fmt.Errorf(
				"unwrap KEK %s: AES-GCM authentication failed — "+
					"does KYC_ROOT_KEK in the environment match the currently active root? (%w)",
				rec.KEKID, err,
			)
		}

		// Re-encrypt the same plaintext KEK under the new root.
		newWrapped, err := aesGCMEncrypt(newRoot, plainKEK)
		zeroBytes(plainKEK) // zero plaintext immediately after use — minimise exposure
		if err != nil {
			zeroBytes(newRoot)
			return 0, fmt.Errorf("re-wrap KEK %s: %w", rec.KEKID, err)
		}

		updates[rec.KEKID] = newWrapped
	}

	// ── Persist all re-wrapped values in one atomic transaction ───────────────
	// If this step fails the DB still holds the original wrapped_key values
	// (old root is still valid). The caller can safely retry.
	if err := e.store.UpdateAllKEKWrappedKeys(updates); err != nil {
		zeroBytes(newRoot)
		return 0, fmt.Errorf(
			"persist re-wrapped KEKs (transaction rolled back — old root still valid): %w",
			err,
		)
	}

	// ── Atomically update the in-memory root on this instance ─────────────────
	// Write lock ensures no concurrent unwrapKEK call sees a partial state.
	// After the lock is released, every new call to unwrapKEK will:
	//   - miss the (now empty) cache
	//   - fetch the new wrapped_key from DB
	//   - decrypt with the new rootKEK → same plaintext KEK as before
	e.mu.Lock()
	newRootCopy := make([]byte, 32)
	copy(newRootCopy, newRoot)
	e.rootKEK = newRootCopy
	e.kekCache = make(map[string][]byte) // evict — re-derives from new root on next hit
	e.activeID = ""                      // force re-fetch of active KEK id from DB
	e.mu.Unlock()

	zeroBytes(newRoot) // zero our local copy; the struct now holds its own

	return len(updates), nil
}

// zeroBytes overwrites every byte of b with 0 to reduce the window during
// which sensitive key material is visible in process memory after use.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
