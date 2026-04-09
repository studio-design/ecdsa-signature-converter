# ECDSA Signature

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A lightweight PHP value object for ECDSA signatures with DER/JWS raw format conversion and mathematical validation.

## Why?

OpenSSL and Cloud KMS (Google Cloud KMS, AWS KMS, Azure Key Vault) return ECDSA signatures in ASN.1 DER format. However, JWT/JWS ([RFC 7518 Section 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4)) requires raw concatenated `R || S` format with fixed-length components.

Major PHP JWT libraries (`firebase/php-jwt`, `lcobucci/jwt`, `web-token/jwt-library`) all handle this conversion internally but expose it only as **private** or **@internal** methods. If you're signing JWTs via Cloud KMS or an HSM — where the private key never leaves the remote service — you need this conversion as a standalone utility.

This library provides an immutable value object that guarantees both format correctness and mathematical validity (`0 < r, s < n`).

## Installation

```bash
composer require studio-design/ecdsa-signature
```

## Requirements

- PHP 8.2+

No extensions required. No external dependencies.

## Usage

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

### Cloud KMS Example

```php
use StudioDesign\EcdsaSignature\Curve;
use StudioDesign\EcdsaSignature\EcdsaSignature;

// 1. Build JWT header and payload
$header  = base64url_encode(json_encode(['alg' => 'ES256', 'typ' => 'JWT', 'kid' => $kid]));
$payload = base64url_encode(json_encode($claims));
$signingInput = "{$header}.{$payload}";

// 2. Send digest to Cloud KMS for signing
$digest = hash('sha256', $signingInput, binary: true);
$derSignature = $kmsClient->asymmetricSign($keyName, $digest);

// 3. Convert DER signature to JWS raw format
$sig = EcdsaSignature::fromDer($derSignature, Curve::P256);

// 4. Assemble JWT
$jwt = "{$signingInput}." . base64url_encode($sig->toRaw());
```

### Accessing Components

```php
$sig = EcdsaSignature::fromRaw($rawSignature, Curve::P256);

$sig->r();      // R component (32 bytes, fixed-length big-endian binary)
$sig->s();      // S component (32 bytes, fixed-length big-endian binary)
$sig->curve();  // Curve::P256
```

### Using Curve from JOSE Algorithm Number

```php
// If you have the JOSE algorithm key-size number (256, 384, 512):
$curve = Curve::from(256);  // Returns Curve::P256

// Or use the enum directly:
$curve = Curve::P256;
$curve = Curve::P384;
$curve = Curve::P521;
```

## Supported Curves

| Algorithm | Curve Enum   | Curve  | Raw Signature Length |
|-----------|-------------|--------|---------------------|
| ES256     | `Curve::P256` | P-256  | 64 bytes            |
| ES384     | `Curve::P384` | P-384  | 96 bytes            |
| ES512     | `Curve::P521` | P-521  | 132 bytes           |

## Validation

Both `fromDer()` and `fromRaw()` validate that signature components satisfy `0 < r, s < n` (where `n` is the curve order). Signatures with zero-valued or out-of-range components are rejected with `InvalidArgumentException`.

This ensures that every `EcdsaSignature` instance represents a mathematically plausible ECDSA signature.

## API Reference

### `EcdsaSignature::fromDer(string $der, Curve $curve): self`

Parse a DER-encoded ECDSA signature into a value object.

- **`$der`** — DER-encoded ASN.1 SEQUENCE containing two INTEGERs (r, s)
- **`$curve`** — The elliptic curve (`Curve::P256`, `Curve::P384`, or `Curve::P521`)
- **Throws** `InvalidArgumentException` if the DER data is malformed or values are out of range

### `EcdsaSignature::fromRaw(string $raw, Curve $curve): self`

Parse a JWS raw (R||S) ECDSA signature into a value object.

- **`$raw`** — Raw signature: R || S (64 bytes for ES256, 96 for ES384, 132 for ES512)
- **`$curve`** — The elliptic curve
- **Throws** `InvalidArgumentException` if the raw signature length is invalid or values are out of range

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

$curve->componentLength();  // Per-component byte length (32, 48, 66)
$curve->order();            // Curve order as fixed-length binary string
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
