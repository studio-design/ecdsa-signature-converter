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
 * Supported JOSE key-size identifiers:
 *   - 256 (ES256 / P-256)  → 64-byte raw signature
 *   - 384 (ES384 / P-384)  → 96-byte raw signature
 *   - 512 (ES512 / P-521)  → 132-byte raw signature (P-521 is a 521-bit curve; JOSE names it "ES512")
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-3.4
 */
final readonly class EcdsaSignatureConverter
{
    /** @var array<int, int> Map of JOSE algorithm key-size number to per-component byte length */
    private const COMPONENT_LENGTHS = [
        256 => 32,  // P-256: 256 / 8
        384 => 48,  // P-384: 384 / 8
        512 => 66,  // P-521 (ES512): ceil(521 / 8) — JOSE uses "512", actual curve is 521 bits
    ];

    /**
     * Bitmask of invalid bits in the leading byte of each component.
     *
     * When the curve's bit length is not a multiple of 8, the leading byte of a
     * fixed-length component has unused high bits that must be zero.
     * P-521 (ES512): 521 bits in 66 bytes → top 7 bits unused → mask 0xFE.
     *
     * @var array<int, int>
     */
    private const LEADING_BYTE_MASKS = [
        256 => 0x00,  // P-256: 256 bits = 32 bytes exactly, all bits used
        384 => 0x00,  // P-384: 384 bits = 48 bytes exactly, all bits used
        512 => 0xFE,  // P-521: 521 bits in 66 bytes, top 7 bits of first byte must be zero
    ];

    /**
     * Convert a DER-encoded ECDSA signature to JWS raw (R||S) format.
     *
     * @param string $der         DER-encoded ASN.1 SEQUENCE containing two INTEGERs (r, s)
     * @param int    $keySizeBits ECDSA key size in bits as used by JOSE algorithm names (256 for ES256/P-256, 384 for ES384/P-384, 512 for ES512/P-521). Note: ES512 uses the P-521 curve (521 bits), yielding 66-byte components.
     *
     * @return string Raw signature: R || S, each component padded to the curve's fixed byte length (32 for ES256, 48 for ES384, 66 for ES512)
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

        $componentLength = self::COMPONENT_LENGTHS[$keySizeBits];

        // Parse DER SEQUENCE envelope
        ['offset' => $offset, 'contentEnd' => $seqEnd] = self::readDer($der);

        // Validate SEQUENCE spans the entire input (no trailing data after SEQUENCE)
        if ($seqEnd !== strlen($der)) {
            throw new InvalidArgumentException('DER signature contains trailing data after SEQUENCE.');
        }

        // Extract INTEGER components R and S
        ['offset' => $offset, 'data' => $r, 'tag' => $rTag] = self::readDer($der, $offset);

        if ($offset >= $seqEnd) {
            throw new InvalidArgumentException('DER SEQUENCE must contain two INTEGER components (R and S), but only one was found.');
        }

        ['offset' => $endPos, 'data' => $s, 'tag' => $sTag] = self::readDer($der, $offset);

        if ($rTag !== 0x02 || $sTag !== 0x02) {
            throw new InvalidArgumentException('DER signature R and S components must be INTEGERs (tag 0x02).');
        }

        // Validate children consumed all SEQUENCE content (no intra-SEQUENCE garbage)
        if ($endPos !== $seqEnd) {
            throw new InvalidArgumentException('DER SEQUENCE content length does not match its declared length.');
        }

        // Defense-in-depth: the tag check above ensures both R and S have INTEGER tag (0x02),
        // which is always primitive, so readDer returns string data (not null). Additionally,
        // readDer rejects zero-length INTEGERs per X.690 Section 8.3.1. This condition is
        // therefore normally unreachable.
        // @codeCoverageIgnoreStart
        if (! is_string($r) || ! is_string($s) || $r === '' || $s === '') {
            throw new InvalidArgumentException('Failed to extract R and S components from DER signature.');
        }
        // @codeCoverageIgnoreEnd

        // Validate DER INTEGER encoding (X.690 Section 8.3.2: minimal encoding required)
        // and strip the sign-padding byte from R and S components.
        $r = self::validateAndStripComponent($r, 'R', $componentLength, $keySizeBits);
        $s = self::validateAndStripComponent($s, 'S', $componentLength, $keySizeBits);

        // Pad to fixed length for JWS format
        $r = str_pad($r, $componentLength, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, $componentLength, "\x00", STR_PAD_LEFT);

        // Validate that components fit within the curve's actual bit range
        self::validateComponentBitRange($r, 'R', $keySizeBits);
        self::validateComponentBitRange($s, 'S', $keySizeBits);

        return $r.$s;
    }

    /**
     * Convert a JWS raw (R||S) ECDSA signature to ASN.1 DER format.
     *
     * @param string $raw         Raw signature: R || S (each component: 32 bytes for ES256, 48 for ES384, 66 for ES512)
     * @param int    $keySizeBits ECDSA key size in bits as used by JOSE algorithm names (256 for ES256/P-256, 384 for ES384/P-384, 512 for ES512/P-521). Note: ES512 uses the P-521 curve (521 bits), yielding 66-byte components.
     *
     * @return string DER-encoded ASN.1 SEQUENCE containing two INTEGERs (r, s)
     *
     * @throws InvalidArgumentException If the raw signature length is invalid or the key size is unsupported
     */
    public static function rawToDer(string $raw, int $keySizeBits): string
    {
        self::validateKeySize($keySizeBits);

        $componentLength = self::COMPONENT_LENGTHS[$keySizeBits];
        $expectedLength = $componentLength * 2;

        if (strlen($raw) !== $expectedLength) {
            throw new InvalidArgumentException("Raw signature must be exactly {$expectedLength} bytes for {$keySizeBits}-bit key, got ".strlen($raw).'.');
        }

        $r = substr($raw, 0, $componentLength);
        $s = substr($raw, $componentLength);

        // Validate that components fit within the curve's actual bit range
        self::validateComponentBitRange($r, 'R', $keySizeBits);
        self::validateComponentBitRange($s, 'S', $keySizeBits);

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
        if (! array_key_exists($keySizeBits, self::COMPONENT_LENGTHS)) {
            throw new InvalidArgumentException(
                "Unsupported key size: {$keySizeBits}. Supported sizes: ".implode(', ', array_keys(self::COMPONENT_LENGTHS)).'.',
            );
        }
    }

    /**
     * Validate that a fixed-length component does not exceed the curve's bit range.
     *
     * For curves whose bit length is not a multiple of 8 (e.g. P-521 = 521 bits
     * in 66 bytes), the leading byte has unused high bits that must be zero.
     *
     * @param string $component Fixed-length component (already padded or from raw input)
     *
     * @throws InvalidArgumentException
     */
    private static function validateComponentBitRange(string $component, string $label, int $keySizeBits): void
    {
        $mask = self::LEADING_BYTE_MASKS[$keySizeBits];

        if ($mask !== 0x00 && (ord($component[0]) & $mask) !== 0) {
            throw new InvalidArgumentException(
                "ECDSA {$label} component exceeds the valid bit range for ES{$keySizeBits} (P-521 values must fit in 521 bits).",
            );
        }
    }

    /**
     * Validate a DER INTEGER component and strip the sign-padding byte for JWS format.
     *
     * DER INTEGERs are signed two's complement — a set high bit means the value is
     * negative, which is invalid for ECDSA R/S values that must be positive.
     * X.690 Section 8.3.2 requires minimal encoding: a leading 0x00 is only permitted
     * when the next byte has its high bit set (sign padding). Non-minimal encodings
     * (unnecessary leading zeros) are rejected as invalid DER.
     *
     * @return string Stripped component value
     *
     * @throws InvalidArgumentException
     */
    private static function validateAndStripComponent(string $value, string $label, int $componentLength, int $keySizeBits): string
    {
        if ((ord($value[0]) & 0x80) !== 0) {
            throw new InvalidArgumentException("DER INTEGER {$label} component is negative, which is invalid for ECDSA signatures.");
        }

        // X.690 Section 8.3.2: reject non-minimal INTEGER encoding.
        // A leading 0x00 is only valid as sign padding when the next byte has its high bit set.
        if (strlen($value) >= 2 && ord($value[0]) === 0x00 && (ord($value[1]) & 0x80) === 0) {
            throw new InvalidArgumentException(
                "DER INTEGER {$label} has non-minimal encoding: unnecessary leading zero byte (X.690 Section 8.3.2).",
            );
        }

        // Strip sign-padding byte if present (0x00 followed by byte with high bit set).
        if (strlen($value) >= 2 && ord($value[0]) === 0x00) {
            $value = substr($value, 1);
        }

        if (strlen($value) > $componentLength) {
            $len = strlen($value);
            throw new InvalidArgumentException(
                "DER INTEGER {$label} value ({$len} bytes) exceeds {$componentLength}-byte limit for {$keySizeBits}-bit key.",
            );
        }

        return $value;
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
     * For constructed types (SEQUENCE), returns null as data and sets the offset
     * to the start of the content area — the caller should parse children from
     * this offset up to the content-end position.
     * For primitive types (INTEGER), returns the raw value bytes and sets the
     * offset to the byte after the last content byte (equal to contentEnd).
     *
     * @return array{offset: int, data: string|null, tag: int, contentEnd: int}
     *
     * @throws InvalidArgumentException
     */
    private static function readDer(string $der, int $offset = 0): array
    {
        $size = strlen($der);

        if ($offset < 0 || $offset >= $size) {
            throw new InvalidArgumentException("DER read offset {$offset} is out of bounds for data length {$size}.");
        }

        $pos = $offset;

        // ASN.1 tag byte (X.690 Section 8.1.2.2):
        //   bits 7-6 = class (Universal=0b00), bit 5 = constructed flag, bits 4-0 = tag number
        $tagByte = ord($der[$pos]);

        // Reject non-Universal class tags (X.690 Section 8.1.2.2: class bits are bits 7-6).
        // ECDSA signatures only use Universal class types (SEQUENCE 0x30, INTEGER 0x02).
        if (($tagByte & 0xC0) !== 0x00) {
            throw new InvalidArgumentException(
                sprintf('DER non-Universal class tag (0x%02X) is not supported for ECDSA signatures.', $tagByte),
            );
        }

        $constructed = ($tagByte & 0x20) !== 0;
        $type = $tagByte & 0x1F;
        $pos++;

        if ($type === 0x1F) {
            throw new InvalidArgumentException('DER multi-byte tag numbers are not supported.');
        }

        if ($pos >= $size) {
            throw new InvalidArgumentException('DER data truncated: missing length byte.');
        }

        // Length
        $len = ord($der[$pos++]);

        if ($len & 0x80) {
            $n = $len & 0x7F;

            if ($n === 0) {
                throw new InvalidArgumentException('DER indefinite-length encoding (0x80) is not permitted.');
            }

            if ($n > 4) {
                throw new InvalidArgumentException('DER length field exceeds 4 bytes, which is unreasonably large for ECDSA signatures.');
            }

            $nBytes = $n;
            $len = 0;

            for ($i = 0; $i < $nBytes && $pos < $size; $i++) {
                $len = ($len << 8) | ord($der[$pos++]);
            }

            if ($i < $nBytes) {
                throw new InvalidArgumentException('DER data truncated: multi-byte length field is incomplete.');
            }

            // Guard against integer overflow on 32-bit PHP: accumulating 4 length bytes via
            // left-shifts can set the sign bit of a 32-bit signed integer, producing a negative
            // $len. Untestable on 64-bit platforms where PHP_INT_SIZE >= 8.
            // @codeCoverageIgnoreStart
            if ($len < 0) {
                throw new InvalidArgumentException('DER length field overflowed integer range.');
            }
            // @codeCoverageIgnoreEnd

            // DER requires shortest possible length encoding
            if ($len < 0x80) {
                throw new InvalidArgumentException('DER non-minimal length encoding: value fits in short form.');
            }
            if ($nBytes > 1 && $len < (1 << (8 * ($nBytes - 1)))) {
                throw new InvalidArgumentException('DER non-minimal length encoding: uses more octets than necessary.');
            }
        }

        if ($pos + $len > $size) {
            throw new InvalidArgumentException('DER data truncated: value extends beyond data length.');
        }

        // Content-end position: for all types, this is the byte after the last content byte
        $contentEnd = $pos + $len;

        // Value: ECDSA signatures contain only SEQUENCE (constructed) and INTEGER (primitive).
        if ($constructed) {
            $data = null;
        } else {
            // X.690 Section 8.3.1: INTEGER contents must be at least one octet
            if ($type === 0x02 && $len === 0) {
                throw new InvalidArgumentException('DER INTEGER must have at least one content octet (X.690 Section 8.3.1).');
            }
            $data = substr($der, $pos, $len);
            $pos += $len;
        }

        return ['offset' => $pos, 'data' => $data, 'tag' => $tagByte, 'contentEnd' => $contentEnd];
    }
}
