# ECDSA Signature Converter

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A lightweight PHP library for converting ECDSA signatures between ASN.1 DER and JWS raw (R||S) formats.

## Why?

OpenSSL and Cloud KMS (Google Cloud KMS, AWS KMS, Azure Key Vault) return ECDSA signatures in ASN.1 DER format. However, JWT/JWS ([RFC 7518 Section 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4)) requires raw concatenated `R || S` format with fixed-length components.

Major PHP JWT libraries (`firebase/php-jwt`, `lcobucci/jwt`, `web-token/jwt-library`) all handle this conversion internally but expose it only as **private** or **@internal** methods. If you're signing JWTs via Cloud KMS or an HSM — where the private key never leaves the remote service — you need this conversion as a standalone utility.

## Installation

```bash
composer require studio-design/ecdsa-signature-converter
```

## Requirements

- PHP 8.2+

No extensions required. No external dependencies.

## Usage

### DER to Raw (for JWT signing)

Convert a DER-encoded ECDSA signature (from OpenSSL or Cloud KMS) to JWS raw format:

```php
use StudioDesign\EcdsaSignature\EcdsaSignatureConverter;

// Sign with OpenSSL (returns DER format)
openssl_sign($payload, $derSignature, $privateKey, OPENSSL_ALGO_SHA256);

// Convert to JWS raw format (R||S)
$rawSignature = EcdsaSignatureConverter::derToRaw($derSignature, keySizeBits: 256);
// $rawSignature is now 64 bytes (32-byte R + 32-byte S)
```

### Raw to DER (for signature verification)

Convert a JWS raw signature back to DER format for OpenSSL verification:

```php
$derSignature = EcdsaSignatureConverter::rawToDer($rawSignature, keySizeBits: 256);

// Verify with OpenSSL (expects DER format)
$result = openssl_verify($payload, $derSignature, $publicKey, OPENSSL_ALGO_SHA256);
```

### Cloud KMS Example

```php
use StudioDesign\EcdsaSignature\EcdsaSignatureConverter;

// 1. Build JWT header and payload
$header  = base64url_encode(json_encode(['alg' => 'ES256', 'typ' => 'JWT', 'kid' => $kid]));
$payload = base64url_encode(json_encode($claims));
$signingInput = "{$header}.{$payload}";

// 2. Send digest to Cloud KMS for signing
$digest = hash('sha256', $signingInput, binary: true);
$derSignature = $kmsClient->asymmetricSign($keyName, $digest);

// 3. Convert DER signature to JWS raw format
$rawSignature = EcdsaSignatureConverter::derToRaw($derSignature, keySizeBits: 256);

// 4. Assemble JWT
$jwt = "{$signingInput}." . base64url_encode($rawSignature);
```

## Supported Key Sizes

| Algorithm | Key Size | Curve | Raw Signature Length |
|-----------|----------|-------|---------------------|
| ES256     | 256 bits | P-256 | 64 bytes            |
| ES384     | 384 bits | P-384 | 96 bytes            |
| ES512     | 512 bits | P-521 | 132 bytes           |

## API Reference

### `EcdsaSignatureConverter::derToRaw(string $der, int $keySizeBits): string`

Converts a DER-encoded ECDSA signature to JWS raw (R||S) format.

- **`$der`** — DER-encoded ASN.1 SEQUENCE containing two INTEGERs (r, s)
- **`$keySizeBits`** — ECDSA key size in bits (256, 384, or 512)
- **Returns** — Raw signature bytes: R (padded) || S (padded)
- **Throws** `InvalidArgumentException` if the DER data is malformed or the key size is unsupported

### `EcdsaSignatureConverter::rawToDer(string $raw, int $keySizeBits): string`

Converts a JWS raw (R||S) ECDSA signature to ASN.1 DER format.

- **`$raw`** — Raw signature: R || S (total length must equal keySizeBits / 8 * 2)
- **`$keySizeBits`** — ECDSA key size in bits (256, 384, or 512)
- **Returns** — DER-encoded ASN.1 SEQUENCE containing two INTEGERs (r, s)
- **Throws** `InvalidArgumentException` if the raw signature length is invalid or the key size is unsupported

## Background

ECDSA produces two integer values (r, s). These can be encoded in two ways:

- **ASN.1 DER** — Variable-length encoding: `SEQUENCE { INTEGER r, INTEGER s }`. This is what OpenSSL and Cloud KMS return.
- **JWS Raw (IEEE P1363)** — Fixed-length concatenation: `R || S`, each padded to the key size. This is what JWT/JWS requires per [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518#section-3.4).

The conversion handles:
- Stripping/adding DER sign-padding bytes (leading `0x00` for positive integers with high bit set)
- Padding/trimming R and S to fixed-length components
- Validating DER structure integrity (SEQUENCE tag, length fields, trailing data detection)

## License

MIT License. See [LICENSE](LICENSE) for details.
