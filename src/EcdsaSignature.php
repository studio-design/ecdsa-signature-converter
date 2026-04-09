<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature;

use InvalidArgumentException;

/**
 * Immutable value object representing an ECDSA signature (r, s) on a named curve.
 *
 * Supports conversion between ASN.1 DER and JWS raw (R||S) formats, and
 * guarantees that both components satisfy 0 < value < n (curve order).
 *
 * Supported JOSE key-size identifiers:
 *   - 256 (ES256 / P-256)  → 64-byte raw signature
 *   - 384 (ES384 / P-384)  → 96-byte raw signature
 *   - 512 (ES512 / P-521)  → 132-byte raw signature
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-3.4
 */
final readonly class EcdsaSignature
{
    /**
     * @param string $r     Fixed-length R component (componentLength bytes, big-endian)
     * @param string $s     Fixed-length S component (componentLength bytes, big-endian)
     * @param Curve  $curve The elliptic curve this signature belongs to
     */
    private function __construct(
        private string $r,
        private string $s,
        private Curve $curve,
    ) {}

    /**
     * Create an EcdsaSignature from a DER-encoded ASN.1 SEQUENCE containing two INTEGERs.
     *
     * @param string $der   DER-encoded signature
     * @param Curve  $curve The elliptic curve
     *
     * @throws InvalidArgumentException If the DER data is malformed or values are out of range
     */
    public static function fromDer(string $der, Curve $curve): self
    {
        if (strlen($der) < 8) {
            throw new InvalidArgumentException('DER signature is too short to be a valid ECDSA signature.');
        }

        if (ord($der[0]) !== 0x30) {
            throw new InvalidArgumentException('DER signature does not start with SEQUENCE tag (0x30).');
        }

        $componentLength = $curve->componentLength();

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
        $r = self::validateAndStripComponent($r, 'R', $curve);
        $s = self::validateAndStripComponent($s, 'S', $curve);

        // Pad to fixed length
        $r = str_pad($r, $componentLength, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, $componentLength, "\x00", STR_PAD_LEFT);

        // Validate 0 < r < n and 0 < s < n
        self::validateRange($r, 'R', $curve);
        self::validateRange($s, 'S', $curve);

        return new self($r, $s, $curve);
    }

    /**
     * Create an EcdsaSignature from a JWS raw (R||S) signature.
     *
     * @param string $raw   Raw signature: R || S (each component padded to fixed length)
     * @param Curve  $curve The elliptic curve
     *
     * @throws InvalidArgumentException If the raw signature length is invalid or values are out of range
     */
    public static function fromRaw(string $raw, Curve $curve): self
    {
        $componentLength = $curve->componentLength();
        $expectedLength = $componentLength * 2;

        if (strlen($raw) !== $expectedLength) {
            throw new InvalidArgumentException("Raw signature must be exactly {$expectedLength} bytes for ES{$curve->value}, got ".strlen($raw).'.');
        }

        $r = substr($raw, 0, $componentLength);
        $s = substr($raw, $componentLength);

        // Validate 0 < r < n and 0 < s < n
        self::validateRange($r, 'R', $curve);
        self::validateRange($s, 'S', $curve);

        return new self($r, $s, $curve);
    }

    /**
     * Encode this signature as ASN.1 DER.
     *
     * @return string DER-encoded SEQUENCE containing two INTEGERs (r, s)
     */
    public function toDer(): string
    {
        $derR = self::toDerInteger($this->r);
        $derS = self::toDerInteger($this->s);

        return self::encodeDer(0x30, $derR.$derS);
    }

    /**
     * Encode this signature as JWS raw (R||S) format.
     *
     * @return string Raw signature: R || S, each component at fixed length
     */
    public function toRaw(): string
    {
        return $this->r.$this->s;
    }

    /**
     * R component as a fixed-length big-endian binary string.
     */
    public function r(): string
    {
        return $this->r;
    }

    /**
     * S component as a fixed-length big-endian binary string.
     */
    public function s(): string
    {
        return $this->s;
    }

    /**
     * The elliptic curve this signature belongs to.
     */
    public function curve(): Curve
    {
        return $this->curve;
    }

    /**
     * Validate that a component value satisfies 0 < value < n (curve order).
     *
     * @param string $value Fixed-length component (componentLength bytes)
     *
     * @throws InvalidArgumentException
     */
    private static function validateRange(string $value, string $label, Curve $curve): void
    {
        $zero = str_repeat("\x00", $curve->componentLength());

        if ($value === $zero) {
            throw new InvalidArgumentException("ECDSA {$label} component must be greater than zero.");
        }

        if (strcmp($value, $curve->order()) >= 0) {
            throw new InvalidArgumentException("ECDSA {$label} component must be less than the curve order for ES{$curve->value}.");
        }
    }

    /**
     * Validate a DER INTEGER component and strip the sign-padding byte.
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
    private static function validateAndStripComponent(string $value, string $label, Curve $curve): string
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

        $componentLength = $curve->componentLength();

        if (strlen($value) > $componentLength) {
            $len = strlen($value);
            throw new InvalidArgumentException(
                "DER INTEGER {$label} value ({$len} bytes) exceeds {$componentLength}-byte limit for ES{$curve->value}.",
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
     * to the start of the content area. For primitive types (INTEGER), returns the
     * raw value bytes.
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

        // ASN.1 tag byte (X.690 Section 8.1.2.2)
        $tagByte = ord($der[$pos]);

        // Reject non-Universal class tags
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

            // Guard against integer overflow on 32-bit PHP
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

        $contentEnd = $pos + $len;

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
