<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature;

use ValueError;

/**
 * ECDSA curve definitions used by JOSE/JWS algorithm identifiers.
 *
 * The int backing value corresponds to the JOSE algorithm key-size number:
 *   - 256 → ES256 / P-256
 *   - 384 → ES384 / P-384
 *   - 512 → ES512 / P-521 (P-521 is a 521-bit curve; JOSE names it "ES512")
 */
enum Curve: int
{
    case P256 = 256;
    case P384 = 384;
    case P521 = 512;

    /**
     * Resolve a curve from a JOSE algorithm name (e.g. "ES256", "ES384", "ES512").
     *
     * @throws ValueError If the algorithm name is not a supported ECDSA algorithm
     */
    public static function fromJoseAlg(string $alg): self
    {
        return match ($alg) {
            'ES256' => self::P256,
            'ES384' => self::P384,
            'ES512' => self::P521,
            default => throw new ValueError("Unknown JOSE algorithm \"{$alg}\". Supported: ES256, ES384, ES512."),
        };
    }

    /**
     * Resolve a curve from an OpenSSL curve name (e.g. "prime256v1", "secp384r1", "secp521r1").
     *
     * @throws ValueError If the curve name is not supported
     */
    public static function fromOpenSslCurveName(string $name): self
    {
        return match ($name) {
            'prime256v1' => self::P256,
            'secp384r1'  => self::P384,
            'secp521r1'  => self::P521,
            default      => throw new ValueError("Unknown OpenSSL curve name \"{$name}\". Supported: prime256v1, secp384r1, secp521r1."),
        };
    }

    /**
     * The JOSE algorithm name for this curve (e.g. "ES256").
     */
    public function joseAlg(): string
    {
        return match ($this) {
            self::P256 => 'ES256',
            self::P384 => 'ES384',
            self::P521 => 'ES512',
        };
    }

    /**
     * The OpenSSL curve name for this curve (e.g. "prime256v1").
     */
    public function openSslCurveName(): string
    {
        return match ($this) {
            self::P256 => 'prime256v1',
            self::P384 => 'secp384r1',
            self::P521 => 'secp521r1',
        };
    }

    /**
     * Per-component byte length for the raw (R||S) signature format.
     */
    public function componentLength(): int
    {
        return match ($this) {
            self::P256 => 32,   // 256 / 8
            self::P384 => 48,   // 384 / 8
            self::P521 => 66,   // ceil(521 / 8)
        };
    }

    /**
     * Curve order (n) as a fixed-length big-endian binary string.
     *
     * The returned string is left-padded to componentLength() bytes so that
     * it can be compared directly against R/S values via strcmp().
     *
     * @see https://www.secg.org/sec2-v2.pdf
     */
    public function order(): string
    {
        /** @var array<int, string> $cache */
        static $cache = [];

        return $cache[$this->value] ??= (string) match ($this) {
            self::P256 => hex2bin('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'),
            self::P384 => hex2bin('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973'),
            self::P521 => hex2bin('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409'),
        };
    }
}
