# ECDSA Signature

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A lightweight PHP value object for ECDSA signatures with DER/JWS raw format conversion and mathematical validation.

## Why?

OpenSSL and Cloud KMS (Google Cloud KMS, AWS KMS, Azure Key Vault) return ECDSA signatures in ASN.1 DER format. However, JWT/JWS ([RFC 7518 Section 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4)) requires raw concatenated `R || S` format with fixed-length components.

Major PHP JWT libraries (`firebase/php-jwt`, `lcobucci/jwt`, `web-token/jwt-library`) all handle this conversion internally but expose it only as **private** or **@internal** methods. If you're signing JWTs via Cloud KMS or an HSM — where the private key never leaves the remote service — you need this conversion as a standalone utility.

This library provides an immutable value object that guarantees both format correctness and mathematical validity (`0 < r, s < n`).

## Non-Goals

This library **does not**:

- Verify ECDSA signatures (use `openssl_verify()` or your KMS provider for that)
- Generate or manage keys
- Build or parse JWTs
- Support non-NIST curves (e.g. secp256k1, Ed25519)

It is a **signature format converter + validated value object**, not a cryptography library.

## Installation

```bash
composer require studio-design/ecdsa-signature
```

## Requirements

- PHP 8.2+

No extensions required. No external dependencies.

## Quick Start

### DER to Raw (for JWT signing)

Convert a DER-encoded ECDSA signature (from OpenSSL or Cloud KMS) to JWS raw format:

```php
use StudioDesign\EcdsaSignature\Curve;
use StudioDesign\EcdsaSignature\EcdsaSignature;

// Sign with OpenSSL (returns DER format)
openssl_sign($payload, $derSignature, $privateKey, OPENSSL_ALGO_SHA256);

// Parse DER and convert to JWS raw format (R||S)
$sig = EcdsaSignature::fromDer($derSignature, Curve::P256);
$rawSignature = $sig->toRaw();
// $rawSignature is now 64 bytes (32-byte R + 32-byte S)
```

### Raw to DER (for signature verification)

Convert a JWS raw signature back to DER format for OpenSSL verification:

```php
$sig = EcdsaSignature::fromRaw($rawSignature, Curve::P256);
$derSignature = $sig->toDer();

// Verify with OpenSSL (expects DER format)
$result = openssl_verify($payload, $derSignature, $publicKey, OPENSSL_ALGO_SHA256);
```

## Choosing a Curve

Multiple ways to select a curve, depending on your context:

```php
use StudioDesign\EcdsaSignature\Curve;

// Direct enum usage
$curve = Curve::P256;

// From a JOSE algorithm name (JWT header "alg" field)
$curve = Curve::fromJoseAlg('ES256');   // → Curve::P256
$curve = Curve::fromJoseAlg('ES384');   // → Curve::P384
$curve = Curve::fromJoseAlg('ES512');   // → Curve::P521

// From an OpenSSL curve name
$curve = Curve::fromOpenSslCurveName('prime256v1');  // → Curve::P256
$curve = Curve::fromOpenSslCurveName('secp384r1');   // → Curve::P384
$curve = Curve::fromOpenSslCurveName('secp521r1');   // → Curve::P521

// From the JOSE key-size integer (256, 384, 512)
$curve = Curve::from(256);  // → Curve::P256

// Reverse lookups
$curve->joseAlg();          // "ES256"
$curve->openSslCurveName(); // "prime256v1"
```

## Usage Examples

### JWT with Cloud KMS

```php
use StudioDesign\EcdsaSignature\Curve;
use StudioDesign\EcdsaSignature\EcdsaSignature;

// 1. Determine curve from JWT algorithm
$alg = 'ES256';
$curve = Curve::fromJoseAlg($alg);

// 2. Build JWT header and payload
$header  = base64url_encode(json_encode(['alg' => $alg, 'typ' => 'JWT', 'kid' => $kid]));
$payload = base64url_encode(json_encode($claims));
$signingInput = "{$header}.{$payload}";

// 3. Send digest to Cloud KMS for signing (returns DER)
$digest = hash('sha256', $signingInput, binary: true);
$derSignature = $kmsClient->asymmetricSign($keyName, $digest);

// 4. Convert DER signature to JWS raw format
$sig = EcdsaSignature::fromDer($derSignature, $curve);

// 5. Assemble JWT
$jwt = "{$signingInput}." . base64url_encode($sig->toRaw());
```

### OpenSSL Sign and Verify

```php
use StudioDesign\EcdsaSignature\Curve;
use StudioDesign\EcdsaSignature\EcdsaSignature;

$curve = Curve::fromOpenSslCurveName('prime256v1');

// Sign (OpenSSL produces DER)
$key = openssl_pkey_new([
    'ec' => ['curve_name' => $curve->openSslCurveName()],
    'private_key_type' => OPENSSL_KEYTYPE_EC,
]);
openssl_sign($payload, $der, $key, OPENSSL_ALGO_SHA256);

// Convert to raw for JWT
$raw = EcdsaSignature::fromDer($der, $curve)->toRaw();

// Later: convert raw back to DER for verification
$derAgain = EcdsaSignature::fromRaw($raw, $curve)->toDer();
openssl_verify($payload, $derAgain, $publicKey, OPENSSL_ALGO_SHA256);
```

### Accessing Components

```php
$sig = EcdsaSignature::fromRaw($rawSignature, Curve::P256);

$sig->r();      // R component (32 bytes, fixed-length big-endian binary)
$sig->s();      // S component (32 bytes, fixed-length big-endian binary)
$sig->curve();  // Curve::P256
```

## Error Handling

The library provides a structured exception hierarchy. All exceptions extend both `EcdsaSignatureException` and PHP's built-in `InvalidArgumentException`, so existing `catch (InvalidArgumentException)` blocks continue to work.

```php
use StudioDesign\EcdsaSignature\Exception\EcdsaSignatureException;
use StudioDesign\EcdsaSignature\Exception\InvalidDerSignature;
use StudioDesign\EcdsaSignature\Exception\InvalidRawSignature;
use StudioDesign\EcdsaSignature\Exception\InvalidSignatureComponent;
use StudioDesign\EcdsaSignature\Exception\UnsupportedCurve;

try {
    $curve = Curve::fromJoseAlg($alg);
    $sig = EcdsaSignature::fromDer($input, $curve);
} catch (UnsupportedCurve $e) {
    // Algorithm name or curve name is not supported
} catch (InvalidDerSignature $e) {
    // DER structure is malformed (bad tag, truncated, non-minimal encoding, etc.)
} catch (InvalidSignatureComponent $e) {
    // R or S is mathematically out of range (zero, >= curve order, oversized)
}

try {
    $sig = EcdsaSignature::fromRaw($input, $curve);
} catch (InvalidRawSignature $e) {
    // Wrong byte length for the given curve
} catch (InvalidSignatureComponent $e) {
    // R or S is mathematically out of range
}

// Or catch everything from this library at once:
try {
    $curve = Curve::fromJoseAlg($alg);
    $sig = EcdsaSignature::fromDer($input, $curve);
} catch (EcdsaSignatureException $e) {
    // Any error from this library — curve resolution, DER parsing, or range validation
}
```

| Exception | Thrown by | Meaning |
|-----------|----------|---------|
| `UnsupportedCurve` | `Curve::fromJoseAlg()`, `Curve::fromOpenSslCurveName()` | Curve identifier is not supported |
| `InvalidDerSignature` | `EcdsaSignature::fromDer()` | DER structure is malformed |
| `InvalidRawSignature` | `EcdsaSignature::fromRaw()` | Raw signature has wrong byte length |
| `InvalidSignatureComponent` | `EcdsaSignature::fromDer()`, `EcdsaSignature::fromRaw()` | R or S fails `0 < value < n` check |
| `EcdsaSignatureException` | (base class) | Any of the above |

## Supported Curves

| JOSE Algorithm | Curve Enum    | OpenSSL Name  | Curve  | Raw Signature Length |
|----------------|--------------|---------------|--------|---------------------|
| ES256          | `Curve::P256` | `prime256v1`  | P-256  | 64 bytes            |
| ES384          | `Curve::P384` | `secp384r1`   | P-384  | 96 bytes            |
| ES512          | `Curve::P521` | `secp521r1`   | P-521  | 132 bytes           |

## Validation

Both `fromDer()` and `fromRaw()` validate that signature components satisfy `0 < r, s < n` (where `n` is the curve order). Signatures with zero-valued or out-of-range components are rejected.

`fromDer()` additionally enforces strict DER encoding rules per X.690: minimal integer encoding, proper tag/length structure, no trailing data.

This ensures that every `EcdsaSignature` instance represents a mathematically plausible ECDSA signature.

## API Reference

### `EcdsaSignature::fromDer(string $der, Curve $curve): self`

Parse a DER-encoded ECDSA signature.

- **Throws** `InvalidDerSignature` if the DER data is structurally malformed
- **Throws** `InvalidSignatureComponent` if R or S is out of range

### `EcdsaSignature::fromRaw(string $raw, Curve $curve): self`

Parse a JWS raw (R||S) ECDSA signature.

- **Throws** `InvalidRawSignature` if the byte length is wrong for the given curve
- **Throws** `InvalidSignatureComponent` if R or S is out of range

### `EcdsaSignature::toDer(): string`

Encode this signature as ASN.1 DER.

### `EcdsaSignature::toRaw(): string`

Encode this signature as JWS raw (R||S) format.

### `EcdsaSignature::r(): string` / `EcdsaSignature::s(): string`

Fixed-length R/S components as big-endian binary strings.

### `EcdsaSignature::curve(): Curve`

The elliptic curve this signature belongs to.

### `Curve` enum

```php
Curve::P256  // ES256, backing value 256
Curve::P384  // ES384, backing value 384
Curve::P521  // ES512, backing value 512

// Factory methods
Curve::from(256);                           // From JOSE key-size integer
Curve::fromJoseAlg('ES256');                // From JOSE algorithm name
Curve::fromOpenSslCurveName('prime256v1');  // From OpenSSL curve name

// Properties
$curve->componentLength();   // Per-component byte length (32, 48, 66)
$curve->order();             // Curve order as fixed-length binary string
$curve->joseAlg();           // JOSE algorithm name ("ES256", "ES384", "ES512")
$curve->openSslCurveName();  // OpenSSL curve name ("prime256v1", "secp384r1", "secp521r1")
```

## Background

ECDSA produces two integer values (r, s). These can be encoded in two ways:

- **ASN.1 DER** — Variable-length encoding: `SEQUENCE { INTEGER r, INTEGER s }`. This is what OpenSSL and Cloud KMS return.
- **JWS Raw (IEEE P1363)** — Fixed-length concatenation: `R || S`, each padded to the key size. This is what JWT/JWS requires per [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518#section-3.4).

The conversion handles:
- Stripping/adding DER sign-padding bytes (leading `0x00` for positive integers with high bit set)
- Padding/trimming R and S to fixed-length components
- Validating DER structure integrity (SEQUENCE tag, length fields, trailing data detection)
- Validating mathematical range (`0 < r, s < n`)

## License

MIT License. See [LICENSE](LICENSE) for details.
