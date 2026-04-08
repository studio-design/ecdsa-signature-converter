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
    /** @var array<int, int> Map of JOSE key-size identifier (in bits) to component byte length */
    private const COMPONENT_LENGTHS = [
        256 => 32,  // P-256: 256 / 8
        384 => 48,  // P-384: 384 / 8
        512 => 66,  // P-521 (ES512): ceil(521 / 8) — JOSE uses "512", actual curve is 521 bits
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

        // Parse DER: SEQUENCE { INTEGER r, INTEGER s }
        [$offset, , , $seqEnd] = self::readDer($der);

        // Validate SEQUENCE spans the entire input (no trailing data after SEQUENCE)
        if ($seqEnd !== strlen($der)) {
            throw new InvalidArgumentException('DER signature contains trailing data after SEQUENCE.');
        }

        [$offset, $r, $rTag] = self::readDer($der, $offset);
        [$endPos, $s, $sTag] = self::readDer($der, $offset);

        if ($rTag !== 0x02 || $sTag !== 0x02) {
            throw new InvalidArgumentException('DER signature R and S components must be INTEGERs (tag 0x02).');
        }

        // Validate children consumed all SEQUENCE content (no intra-SEQUENCE garbage)
        if ($endPos !== $seqEnd) {
            throw new InvalidArgumentException('DER SEQUENCE content length does not match its declared length.');
        }

        // Defense-in-depth: readDer already rejects zero-length INTEGERs (X.690 Section 8.3.1).
        // @codeCoverageIgnoreStart
        if ($r === '' || $s === '') {
            throw new InvalidArgumentException('Failed to extract R and S components from DER signature.');
        }
        // @codeCoverageIgnoreEnd

        // Validate and strip leading zeros from R and S components.
        // We intentionally tolerate non-minimal INTEGER encoding (extra leading 0x00 bytes
        // beyond the sign pad) for interoperability with non-conformant encoders, even though
        // strict DER (X.690 Section 8.3.2) would reject them.
        $r = self::validateAndStripComponent($r, 'R', $componentLength, $keySizeBits);
        $s = self::validateAndStripComponent($s, 'S', $componentLength, $keySizeBits);

        // Pad to fixed length for JWS format
        $r = str_pad($r, $componentLength, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, $componentLength, "\x00", STR_PAD_LEFT);

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
     * Validate a DER INTEGER component and strip leading zeros for JWS format.
     *
     * DER INTEGERs are signed two's complement — a set high bit means the value is
     * negative, which is invalid for ECDSA R/S values that must be positive.
     * After rejecting negatives, leading zeros are stripped to produce a minimal
     * unsigned big-endian value for fixed-length JWS padding.
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

        $value = ltrim($value, "\x00");

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
     * For constructed types (SEQUENCE), returns null as data — the caller
     * should continue reading child elements from the returned offset.
     * For primitive types (INTEGER), returns the raw value bytes.
     *
     * @return array{int, string|null, int, int} New offset, decoded value, raw tag byte, and content-end position
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
        //   bits 7-6 = class (0x00 = Universal), bit 5 = constructed (0x20), bits 4-0 = tag number
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

            // Guard against integer overflow on 32-bit PHP where $len could wrap
            // (untestable on 64-bit platforms where 4-byte shifts cannot produce negative values)
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

        return [$pos, $data, $tagByte, $contentEnd];
    }
}
