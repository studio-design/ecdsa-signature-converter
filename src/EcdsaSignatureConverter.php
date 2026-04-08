<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature;

use InvalidArgumentException;

/**
 * Converts ECDSA signatures from ASN.1 DER to JWS raw (R||S) format and vice versa.
 *
 * OpenSSL and Cloud KMS return DER-encoded ECDSA signatures, but JWT/JWS (RFC 7518 Section 3.4)
 * requires raw concatenated (R || S) format with fixed-length components.
 *
 * Supported key sizes:
 *   - 256 bits (ES256 / P-256)  → 64-byte raw signature
 *   - 384 bits (ES384 / P-384)  → 96-byte raw signature
 *   - 512 bits (ES512 / P-521)  → 132-byte raw signature
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-3.4
 */
final readonly class EcdsaSignatureConverter
{
    private const SUPPORTED_KEY_SIZES = [256, 384, 512];

    /**
     * Convert a DER-encoded ECDSA signature to JWS raw (R||S) format.
     *
     * @param string $der         DER-encoded ASN.1 SEQUENCE containing two INTEGERs (r, s)
     * @param int    $keySizeBits ECDSA key size in bits (256 for ES256, 384 for ES384, 512 for ES512)
     *
     * @return string Raw signature: R (padded to keySizeBits / 8) || S (padded to keySizeBits / 8)
     *
     * @throws InvalidArgumentException If the DER data is malformed or the key size is unsupported
     */
    public static function derToRaw(string $der, int $keySizeBits): string
    {
        self::validateKeySize($keySizeBits);

        if (strlen($der) < 8) {
            throw new InvalidArgumentException('DER signature is too short to be a valid ECDSA signature.');
        }

        if (ord($der[0]) !== 0x30) {
            throw new InvalidArgumentException('DER signature does not start with SEQUENCE tag (0x30).');
        }

        $componentLength = $keySizeBits / 8;

        // Parse DER: SEQUENCE { INTEGER r, INTEGER s }
        [$offset] = self::readDer($der);
        [$offset, $r] = self::readDer($der, $offset);
        [$endPos, $s] = self::readDer($der, $offset);

        if ($endPos !== strlen($der)) {
            throw new InvalidArgumentException('DER signature contains trailing data after R and S components.');
        }

        if (! is_string($r) || $r === '' || ! is_string($s) || $s === '') {
            throw new InvalidArgumentException('Failed to extract R and S components from DER signature.');
        }

        // Strip DER sign-padding: DER INTEGERs prepend 0x00 when the high bit is set
        // to keep the value positive. JWS raw format uses unsigned big-endian integers.
        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        // Pad to fixed length for JWS format
        $r = str_pad($r, $componentLength, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, $componentLength, "\x00", STR_PAD_LEFT);

        return $r.$s;
    }

    /**
     * Convert a JWS raw (R||S) ECDSA signature to ASN.1 DER format.
     *
     * @param string $raw         Raw signature: R || S (each component must be keySizeBits / 8 bytes)
     * @param int    $keySizeBits ECDSA key size in bits (256 for ES256, 384 for ES384, 512 for ES512)
     *
     * @return string DER-encoded ASN.1 SEQUENCE containing two INTEGERs (r, s)
     *
     * @throws InvalidArgumentException If the raw signature length is invalid or the key size is unsupported
     */
    public static function rawToDer(string $raw, int $keySizeBits): string
    {
        self::validateKeySize($keySizeBits);

        $componentLength = $keySizeBits / 8;
        $expectedLength = $componentLength * 2;

        if (strlen($raw) !== $expectedLength) {
            throw new InvalidArgumentException("Raw signature must be exactly {$expectedLength} bytes for {$keySizeBits}-bit key, got ".strlen($raw).'.');
        }

        $r = substr($raw, 0, $componentLength);
        $s = substr($raw, $componentLength);

        $derR = self::toDerInteger($r);
        $derS = self::toDerInteger($s);

        $derBody = $derR.$derS;

        return self::encodeDer(0x30, $derBody);
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function validateKeySize(int $keySizeBits): void
    {
        if (! in_array($keySizeBits, self::SUPPORTED_KEY_SIZES, true)) {
            throw new InvalidArgumentException(
                "Unsupported key size: {$keySizeBits}. Supported sizes: ".implode(', ', self::SUPPORTED_KEY_SIZES).'.',
            );
        }
    }

    /**
     * Encode a raw unsigned big-endian integer as a DER INTEGER.
     */
    private static function toDerInteger(string $data): string
    {
        // Strip leading zeros (but keep at least one byte)
        $data = ltrim($data, "\x00") ?: "\x00";

        // Add sign-padding if high bit is set (DER INTEGERs are signed two's complement)
        if (ord($data[0]) & 0x80) {
            $data = "\x00".$data;
        }

        return self::encodeDer(0x02, $data);
    }

    /**
     * Encode a DER tag-length-value triplet.
     */
    private static function encodeDer(int $tag, string $value): string
    {
        $len = strlen($value);

        if ($len < 0x80) {
            return chr($tag).chr($len).$value;
        }

        // Long-form length encoding
        $lenBytes = '';
        $temp = $len;

        while ($temp > 0) {
            $lenBytes = chr($temp & 0xFF).$lenBytes;
            $temp >>= 8;
        }

        return chr($tag).chr(0x80 | strlen($lenBytes)).$lenBytes.$value;
    }

    /**
     * Read a single DER tag-length-value triplet.
     *
     * For constructed types (SEQUENCE), returns null as data — the caller
     * should continue reading child elements from the returned offset.
     * For primitive types (INTEGER), returns the raw value bytes.
     * For BIT STRING, skips the unused-bits octet.
     *
     * @return array{int, string|null} New offset and decoded value
     *
     * @throws InvalidArgumentException
     */
    private static function readDer(string $der, int $offset = 0): array
    {
        $size = strlen($der);

        if ($offset >= $size) {
            throw new InvalidArgumentException("DER read offset {$offset} exceeds data length {$size}.");
        }

        $pos = $offset;

        // Bit 5 of ASN.1 tag byte: 0 = primitive, 1 = constructed (SEQUENCE, SET, etc.)
        $constructed = (ord($der[$pos]) >> 5) & 0x01;
        $type = ord($der[$pos++]) & 0x1F;

        if ($pos >= $size) {
            throw new InvalidArgumentException('DER data truncated: missing length byte.');
        }

        // Length
        $len = ord($der[$pos++]);

        if ($len & 0x80) {
            $n = $len & 0x7F;
            $len = 0;

            while ($n-- && $pos < $size) {
                $len = ($len << 8) | ord($der[$pos++]);
            }

            // Verify all length bytes were consumed (post-decrement leaves $n at -1 on normal exit)
            if ($n >= 0) {
                throw new InvalidArgumentException('DER data truncated: multi-byte length field is incomplete.');
            }
        }

        if ($pos + $len > $size) {
            throw new InvalidArgumentException('DER data truncated: value extends beyond data length.');
        }

        // Value
        if ($type === 0x03) {
            // BIT STRING: skip padding indicator octet
            if ($len < 1) {
                throw new InvalidArgumentException('DER BIT STRING has invalid length.');
            }
            $pos++;
            $data = substr($der, $pos, $len - 1);
            $pos += $len - 1;
        } elseif (! $constructed) {
            $data = substr($der, $pos, $len);
            $pos += $len;
        } else {
            $data = null;
        }

        return [$pos, $data];
    }
}
