# WorkGuard Policy Signing Specification

> **Status:** Normative. All components (control-plane signer, Windows agent verifier) must
> implement exactly this specification. Do not deviate without a documented ADR and a
> coordinated version bump.

## 1. Purpose

This document is the single source of truth for how WorkGuard signs and verifies policy
envelopes. It exists to ensure that the API signing service and the Windows endpoint agent
can independently agree on what constitutes a valid policy without ambiguity in encoding,
algorithm selection, or key management.

## 2. Signature algorithm

**Algorithm:** Ed25519 (RFC 8032).

Rationale:
- Fixed 64-byte signature; no algorithm-negotiation attack surface.
- No padding oracle or hash-algorithm agility risks.
- Well-supported in .NET (`System.Security.Cryptography.Ed25519`), Python (`cryptography`
  >= 2.6 / `PyNaCl`), and all major HSM vendors.
- Fast verification on constrained endpoints.

The agent **must** reject any policy envelope that specifies a different algorithm. There is
no algorithm field for the agent to read; the algorithm is fixed by this specification. A
future algorithm migration requires a new `signing_spec_version` field (see §7).

## 3. Canonical encoding

**Format:** JSON Canonicalization Scheme (JCS), RFC 8785.

The signed byte string is the JCS-canonical encoding of the **policy envelope object**
defined in §4. JCS deterministically sorts object keys and serializes numbers and strings
without ambiguity, eliminating signature bypass via field-order manipulation.

Implementation notes:
- Apply JCS to the envelope object **before** adding the `signature` field.
- The signature is computed over the UTF-8 bytes of the JCS output.
- Do not re-serialize after adding the signature; verify by stripping the `signature` field,
  re-applying JCS, and checking the result against the stored digest and signature.

Reference implementations:
- Python: `jcs` package (`pip install jcs`).
- .NET: implement RFC 8785 or use a reviewed open-source library; verify the implementation
  against the RFC 8785 test vectors before use in production.

## 4. Signed envelope structure

The control plane returns the following object from `GET /agent/policies/current`. The
`signature` field is computed last and covers the JCS encoding of every other top-level
field.

```json
{
  "spec_version": "1",
  "policy_id": "<uuid>",
  "policy_version": 12,
  "schema_version": "1.0.0",
  "issued_at": "<RFC 3339 UTC>",
  "expires_at": "<RFC 3339 UTC>",
  "target_device_id": "<uuid>",
  "digest_sha256": "<lowercase hex SHA-256 of the canonical policy bytes>",
  "key_id": "<kid string matching a key in the verification key set>",
  "policy": { ... },
  "signature": "<standard base64 of the 64-byte Ed25519 signature>"
}
```

### Fields covered by the signature

All fields **except** `signature` itself are included in the signed byte string:

```
spec_version, policy_id, policy_version, schema_version, issued_at, expires_at,
target_device_id, digest_sha256, key_id, policy
```

The agent MUST verify that the JCS encoding of these fields, signed with the Ed25519 key
identified by `key_id`, produces the value in `signature`.

### `digest_sha256`

A lowercase hex SHA-256 digest of the JCS-canonical bytes of the inner `policy` object only
(not the full envelope). This allows the agent to separately confirm that the policy body has
not been truncated or corrupted, independent of the signature check.

### `key_id`

An opaque string (max 128 chars, `[a-zA-Z0-9_-]+`) identifying which public key from the
verification key set (see §5) was used to sign this envelope. The agent uses `key_id` to
look up the correct public key; it does not trust any public key embedded in the envelope.

## 5. Key management

### Signing key (private)

- Stored in a managed KMS/HSM service (e.g., AWS KMS with Ed25519 key type, Azure Key Vault,
  GCP Cloud KMS, or an on-premises HSM with PKCS#11 interface).
- Never written to disk, environment variables, source code, or application logs.
- Accessible only to the designated policy-release service account, not to ordinary
  administrator accounts.
- A separate signing key is used per environment (local, staging, production).
- Key rotation: generate a new key pair, add the new public key to the verification key set
  with a new `kid`, begin signing new policies with the new key, allow existing valid policies
  to expire naturally, then remove the old public key from the key set.

### Verification key set (public)

- Published as a JSON Web Key Set (RFC 7517 JWKS) at the URL configured in
  `POLICY_VERIFYING_KEY_SET_URL`.
- The JWKS endpoint is served over TLS, access-controlled to enrolled devices only, and
  cached by the agent for the duration of a policy's validity period.
- Each key entry includes: `kty`, `crv`, `x` (base64url-encoded public key bytes), and `kid`.
- The agent caches the key set and refreshes it before accepting a new `kid` it has not seen.
- The agent rejects a `kid` that does not appear in the cached or freshly fetched key set.

### Key set example

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url of 32-byte public key>",
      "kid": "wg-policy-2026-01",
      "use": "sig"
    }
  ]
}
```

## 6. Agent verification procedure

The agent MUST perform the following checks in order. Failure at any step MUST result in
rejection of the new policy, preservation of the last-known-good policy, and emission of a
`policy.rejected` security event with the specific failure reason.

1. **Parse:** Deserialize the JSON envelope; reject if parsing fails.
2. **spec_version:** Verify `spec_version == "1"`; reject unknown versions.
3. **target_device_id:** Verify matches the agent's own enrolled device ID.
4. **issued_at / expires_at:** Verify `issued_at <= now() <= expires_at` (allow ±30 s clock
   skew); reject if expired or not yet valid.
5. **policy_version monotonicity:** Verify `policy_version > last_successfully_applied_version`
   (or equal if re-applying the same version after a restart); reject downgrade attempts.
6. **key_id lookup:** Look up `key_id` in the cached or freshly fetched JWKS; reject if not
   found.
7. **Signature verification:** Remove the `signature` field, apply JCS to the remaining
   object, verify the Ed25519 signature using the looked-up public key; reject if invalid.
8. **digest_sha256:** Compute the SHA-256 of the JCS-canonical bytes of the `policy` object;
   verify it matches `digest_sha256`; reject if not.
9. **Schema validation:** Validate the `policy` object against the versioned JSON schema for
   `schema_version`; reject unknown critical fields and invalid values.
10. **Apply:** Pass the validated policy to the enforcement adapters.

## 7. Version migration

If a future algorithm migration is required (e.g., post-quantum), the procedure is:

1. Introduce `spec_version: "2"` with the new algorithm documented in an updated revision of
   this file.
2. Deploy updated agents that understand both `"1"` and `"2"` before cutting over signing.
3. Sign all new policies with `spec_version: "2"`.
4. Remove `spec_version: "1"` support only after all agents have been updated and verified.

Never remove support for an active spec_version before confirming all enrolled devices have
updated.

## 8. Anti-patterns explicitly prohibited

- Do not embed the signing algorithm as a negotiable field in the envelope.
- Do not embed the public key in the envelope; the agent fetches it from the JWKS endpoint.
- Do not use HMAC with a shared secret; per-device authentication uses the device credential,
  not the policy signing key.
- Do not sign a re-serialized (non-JCS) JSON object; serialization order affects the bytes.
- Do not reuse the policy signing key as the TLS certificate private key or device credential.
- Do not log the raw policy bytes or signature in plaintext application logs.

## 9. Test vectors

Before shipping the first release, generate and commit a test-vector file
(`tests/signing/vectors.json`) containing at least:

- A valid signed envelope that the agent must accept.
- An envelope with a flipped bit in the `signature`; the agent must reject it.
- An envelope with `policy_version` lower than the last applied; the agent must reject it.
- An envelope with `expires_at` in the past; the agent must reject it.
- An envelope with `target_device_id` mismatched; the agent must reject it.
- An envelope with an unknown `kid`; the agent must reject it.
- An envelope with `spec_version: "99"`; the agent must reject it.

The API signing service and the Windows agent must independently pass all test vectors before
the Phase 2 exit gate.
