<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature\Tests;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use StudioDesign\EcdsaSignature\EcdsaSignatureConverter;

final class EcdsaSignatureConverterTest extends TestCase
{
    /**
     * Create an EC key for the given curve, compatible with both PHP 8.2/8.3 and PHP 8.4+.
     */
    private static function createEcKey(string $curve = 'prime256v1'): OpenSSLAsymmetricKey
    {
        // PHP 8.4 changed the openssl_pkey_new() config format for EC keys
        $key = openssl_pkey_new([
            'ec'               => ['curve_name' => $curve],
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);

        if ($key === false) {
            // Fallback for PHP 8.2/8.3
            $key = openssl_pkey_new([
                'curve_name'       => $curve,
                'private_key_type' => OPENSSL_KEYTYPE_EC,
            ]);
        }

        assert($key instanceof OpenSSLAsymmetricKey);

        return $key;
    }
    // ---------------------------------------------------------------
    // derToRaw
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('derToRaw: throws for unsupported key size')]
    public function der_to_raw_throws_for_unsupported_key_size(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported key size: 128');

        EcdsaSignatureConverter::derToRaw('dummy', 128);
    }

    #[Test]
    #[TestDox('derToRaw: throws for too-short DER data')]
    public function der_to_raw_throws_for_short_der(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('too short');

        EcdsaSignatureConverter::derToRaw("\x30\x00", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws when DER does not start with SEQUENCE tag')]
    public function der_to_raw_throws_for_invalid_sequence_tag(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('SEQUENCE tag');

        EcdsaSignatureConverter::derToRaw("\x02\x01\x00\x02\x01\x00\x00\x00", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws for trailing data after SEQUENCE')]
    public function der_to_raw_throws_for_trailing_data(): void
    {
        $ecKey = self::createEcKey();

        $this->assertTrue(openssl_sign('test-payload', $der, $ecKey, OPENSSL_ALGO_SHA256));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('trailing data');

        EcdsaSignatureConverter::derToRaw($der."\x00", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws for truncated multi-byte length field')]
    public function der_to_raw_throws_for_truncated_multi_byte_length(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('multi-byte length field is incomplete');

        // SEQUENCE(len=6) -> INTEGER(len=1, val=0x01) + INTEGER with 3-byte long-form length but only 2 bytes remain
        EcdsaSignatureConverter::derToRaw("\x30\x06\x02\x01\x01\x02\x83\x00", 256);
    }

    // ---------------------------------------------------------------
    // rawToDer
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('rawToDer: throws for too-short raw signature')]
    public function raw_to_der_throws_for_short_raw(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('exactly 64 bytes');

        EcdsaSignatureConverter::rawToDer(str_repeat("\x01", 63), 256);
    }

    #[Test]
    #[TestDox('rawToDer: throws for too-long raw signature')]
    public function raw_to_der_throws_for_long_raw(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('exactly 64 bytes');

        EcdsaSignatureConverter::rawToDer(str_repeat("\x01", 65), 256);
    }

    #[Test]
    #[TestDox('rawToDer: throws for unsupported key size')]
    public function raw_to_der_throws_for_unsupported_key_size(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported key size');

        EcdsaSignatureConverter::rawToDer('dummy', 192);
    }

    #[Test]
    #[TestDox('rawToDer: output starts with SEQUENCE tag')]
    public function raw_to_der_output_starts_with_sequence(): void
    {
        $raw = str_repeat("\x01", 64);
        $der = EcdsaSignatureConverter::rawToDer($raw, 256);

        $this->assertSame(0x30, ord($der[0]));
    }

    // ---------------------------------------------------------------
    // Edge cases
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('derToRaw: throws when R or S component has non-INTEGER tag')]
    public function der_to_raw_throws_for_non_integer_tag(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('must be INTEGERs');

        // SEQUENCE(len=6) containing OCTET_STRING(tag=0x04, len=1, val=0x01) + INTEGER(len=1, val=0x01)
        EcdsaSignatureConverter::derToRaw("\x30\x06\x04\x01\x01\x02\x01\x01", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws for empty string input')]
    public function der_to_raw_throws_for_empty_input(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('too short');

        EcdsaSignatureConverter::derToRaw('', 256);
    }

    #[Test]
    #[TestDox('rawToDer: handles R component with high bit set (needs sign padding in DER)')]
    public function raw_to_der_handles_high_bit_r(): void
    {
        $r = str_repeat("\xFF", 32);
        $s = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $raw = $r.$s;

        $der = EcdsaSignatureConverter::rawToDer($raw, 256);

        $this->assertSame(0x30, ord($der[0]));

        $rawAgain = EcdsaSignatureConverter::derToRaw($der, 256);
        $this->assertSame($raw, $rawAgain);
    }

    #[Test]
    #[TestDox('rawToDer: handles zero-value R component')]
    public function raw_to_der_handles_zero_r(): void
    {
        $r = str_repeat("\x00", 32);
        $s = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $raw = $r.$s;

        $der = EcdsaSignatureConverter::rawToDer($raw, 256);
        $rawAgain = EcdsaSignatureConverter::derToRaw($der, 256);

        $this->assertSame($raw, $rawAgain);
    }

    #[Test]
    #[TestDox('rawToDer: handles maximum-value R and S components (all 0xFF)')]
    public function raw_to_der_handles_max_values(): void
    {
        $raw = str_repeat("\xFF", 64);

        $der = EcdsaSignatureConverter::rawToDer($raw, 256);
        $rawAgain = EcdsaSignatureConverter::derToRaw($der, 256);

        $this->assertSame($raw, $rawAgain);
    }

    #[Test]
    #[TestDox('rawToDer: handles minimum non-zero R and S (value = 1)')]
    public function raw_to_der_handles_min_values(): void
    {
        $r = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $s = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $raw = $r.$s;

        $der = EcdsaSignatureConverter::rawToDer($raw, 256);
        $rawAgain = EcdsaSignatureConverter::derToRaw($der, 256);

        $this->assertSame($raw, $rawAgain);
    }

    #[Test]
    #[TestDox('derToRaw: handles DER with non-minimal integer encoding (extra leading zeros)')]
    public function der_to_raw_handles_non_minimal_integers(): void
    {
        // SEQUENCE { INTEGER(0x00 0x00 0x01), INTEGER(0x00 0x01) } — not strictly valid DER (non-minimal encoding), but tolerated by this parser
        $der = "\x30\x09\x02\x03\x00\x00\x01\x02\x02\x00\x01";

        $raw = EcdsaSignatureConverter::derToRaw($der, 256);

        $this->assertSame(64, strlen($raw));
        $this->assertSame(str_pad("\x01", 32, "\x00", STR_PAD_LEFT), substr($raw, 0, 32));
        $this->assertSame(str_pad("\x01", 32, "\x00", STR_PAD_LEFT), substr($raw, 32));
    }

    #[Test]
    #[TestDox('rawToDer: handles both R and S as zero')]
    public function raw_to_der_handles_both_zero(): void
    {
        $raw = str_repeat("\x00", 64);

        $der = EcdsaSignatureConverter::rawToDer($raw, 256);
        $rawAgain = EcdsaSignatureConverter::derToRaw($der, 256);

        $this->assertSame($raw, $rawAgain);
    }

    #[Test]
    #[TestDox('rawToDer: ES512 all-0xFF triggers long-form DER SEQUENCE length encoding')]
    public function raw_to_der_es512_long_form_length(): void
    {
        // ES512: 66-byte R + 66-byte S = 132 bytes raw
        // All 0xFF → each DER INTEGER gets sign-padding (67 bytes) + tag/len (2) = 69 bytes
        // SEQUENCE body = 138 bytes >= 128 → long-form length encoding
        $raw = str_repeat("\xFF", 132);

        $der = EcdsaSignatureConverter::rawToDer($raw, 512);

        // Verify long-form length: 0x30 0x81 0x8A (SEQUENCE, 1-byte long-form, len=138)
        $this->assertSame(0x30, ord($der[0]));
        $this->assertSame(0x81, ord($der[1]));
        $this->assertSame(138, ord($der[2]));

        $rawAgain = EcdsaSignatureConverter::derToRaw($der, 512);
        $this->assertSame($raw, $rawAgain);
    }

    #[Test]
    #[TestDox('derToRaw: throws when DER INTEGER value extends beyond data length')]
    public function der_to_raw_throws_for_truncated_value(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('value extends beyond data length');

        // SEQUENCE(len=6), INTEGER(len=5) but only 4 bytes of value remain
        EcdsaSignatureConverter::derToRaw("\x30\x06\x02\x05\x01\x02\x03\x04", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws when second INTEGER has missing length byte')]
    public function der_to_raw_throws_for_missing_length_byte(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('missing length byte');

        // SEQUENCE(len=6), INTEGER(len=3, val=0x00 0x00 0x01), then bare tag 0x02 with no length
        EcdsaSignatureConverter::derToRaw("\x30\x06\x02\x03\x00\x00\x01\x02", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws when DER INTEGER has zero length')]
    public function der_to_raw_throws_for_zero_length_integer(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at least one content octet');

        // SEQUENCE(len=8), INTEGER(len=0) + INTEGER(len=4, val=0x00 0x00 0x00 0x01)
        EcdsaSignatureConverter::derToRaw("\x30\x08\x02\x00\x02\x04\x00\x00\x00\x01", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws when DER INTEGER value exceeds component length')]
    public function der_to_raw_throws_for_oversized_integer(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('R value (33 bytes) exceeds');

        // SEQUENCE containing INTEGER with 33 non-zero bytes (exceeds 32-byte ES256 component)
        $rValue = str_repeat("\x01", 33);
        $sValue = "\x01";
        $derR = "\x02".chr(strlen($rValue)).$rValue;
        $derS = "\x02".chr(strlen($sValue)).$sValue;
        $body = $derR.$derS;
        $der = "\x30".chr(strlen($body)).$body;

        EcdsaSignatureConverter::derToRaw($der, 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws for DER indefinite-length encoding (0x80)')]
    public function der_to_raw_throws_for_indefinite_length(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('indefinite-length');

        // SEQUENCE with indefinite-length encoding (0x80) — forbidden in DER
        EcdsaSignatureConverter::derToRaw("\x30\x80\x02\x01\x01\x02\x01\x01", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws for non-Universal class tag (context-specific)')]
    public function der_to_raw_throws_for_non_universal_class_tag(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('non-Universal class tag');

        // SEQUENCE(len=6) containing context-specific tag 0xA0 (class=10, constructed, tag=0) + INTEGER(len=1, val=0x01)
        EcdsaSignatureConverter::derToRaw("\x30\x06\xA0\x01\x01\x02\x01\x01", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws for application class tag')]
    public function der_to_raw_throws_for_application_class_tag(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('non-Universal class tag');

        // SEQUENCE(len=6) containing application class tag 0x42 (class=01, primitive, tag=2) + INTEGER(len=1, val=0x01)
        EcdsaSignatureConverter::derToRaw("\x30\x06\x42\x01\x01\x02\x01\x01", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws for multi-byte ASN.1 tag number')]
    public function der_to_raw_throws_for_multi_byte_tag(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('multi-byte tag');

        // SEQUENCE containing element with tag 0x1F (signals multi-byte tag number)
        EcdsaSignatureConverter::derToRaw("\x30\x06\x1F\x01\x01\x02\x01\x01", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws when S component has non-INTEGER tag (R is valid INTEGER)')]
    public function der_to_raw_throws_for_non_integer_s_tag(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('must be INTEGERs');

        // SEQUENCE(len=6) containing INTEGER(tag=0x02, len=1, val=0x01) + OCTET_STRING(tag=0x04, len=1, val=0x01)
        EcdsaSignatureConverter::derToRaw("\x30\x06\x02\x01\x01\x04\x01\x01", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws for negative DER INTEGER (high bit set without sign padding)')]
    public function der_to_raw_throws_for_negative_integer(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('R component is negative');

        // SEQUENCE(len=6) containing INTEGER(val=0xFF = -1) + INTEGER(val=0x01)
        EcdsaSignatureConverter::derToRaw("\x30\x06\x02\x01\xFF\x02\x01\x01", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws when SEQUENCE content length does not match parsed children')]
    public function der_to_raw_throws_for_sequence_length_mismatch(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('SEQUENCE content length');

        // SEQUENCE(len=8) but children only consume 6 bytes, with 2 bytes garbage inside SEQUENCE
        EcdsaSignatureConverter::derToRaw("\x30\x08\x02\x01\x01\x02\x01\x01\x00\x00", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws for non-minimal DER length encoding (long-form for value < 128)')]
    public function der_to_raw_throws_for_non_minimal_length(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('non-minimal');

        // SEQUENCE with long-form length encoding 0x81 0x06 (value 6 fits in short form)
        // followed by INTEGER(len=1, val=0x01) + INTEGER(len=1, val=0x01)
        EcdsaSignatureConverter::derToRaw("\x30\x81\x06\x02\x01\x01\x02\x01\x01", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws for non-minimal multi-byte DER length encoding (2-byte form for value that fits in 1-byte form)')]
    public function der_to_raw_throws_for_non_minimal_multi_byte_length(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('more octets than necessary');

        // Second INTEGER uses 2-byte long-form length 0x82 0x00 0x80 (value=128),
        // which fits in 1-byte long-form 0x81 0x80. This triggers the multi-byte
        // non-minimal check ($nBytes > 1 && $len < (1 << (8 * ($nBytes - 1)))).
        $secondIntValue = str_repeat("\x00", 128);
        $secondInt = "\x02\x82\x00\x80".$secondIntValue;
        $firstInt = "\x02\x01\x01";
        $body = $firstInt.$secondInt;
        // SEQUENCE body = 135 bytes, needs long-form: 0x30 0x81 0x87
        $der = "\x30\x81\x87".$body;

        EcdsaSignatureConverter::derToRaw($der, 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws for negative DER INTEGER S component (R is valid)')]
    public function der_to_raw_throws_for_negative_s_integer(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('S component is negative');

        // SEQUENCE(len=6) containing INTEGER(val=0x01) + INTEGER(val=0xFF = -1)
        EcdsaSignatureConverter::derToRaw("\x30\x06\x02\x01\x01\x02\x01\xFF", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws when DER INTEGER S has zero length (R is valid)')]
    public function der_to_raw_throws_for_zero_length_s_integer(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at least one content octet');

        // SEQUENCE(len=8), INTEGER(len=4, val=0x00 0x00 0x00 0x01) + INTEGER(len=0)
        EcdsaSignatureConverter::derToRaw("\x30\x08\x02\x04\x00\x00\x00\x01\x02\x00", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws when DER length field exceeds 4 bytes')]
    public function der_to_raw_throws_for_excessive_length_bytes(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('exceeds 4 bytes');

        // SEQUENCE(len=11) -> INTEGER with 5-byte length field (0x85) — unreasonably large
        EcdsaSignatureConverter::derToRaw("\x30\x0B\x02\x85\x00\x00\x00\x00\x01\x02\x01\x01\x01", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws when DER read offset exceeds data length (SEQUENCE has only one child)')]
    public function der_to_raw_throws_for_offset_exceeds_data(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('out of bounds');

        // SEQUENCE(len=6) containing only one INTEGER(len=4) that consumes all SEQUENCE content
        EcdsaSignatureConverter::derToRaw("\x30\x06\x02\x04\x00\x00\x00\x01", 256);
    }

    #[Test]
    #[TestDox('derToRaw: throws when DER INTEGER S value exceeds component length')]
    public function der_to_raw_throws_for_oversized_s_integer(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('S value (33 bytes) exceeds');

        // SEQUENCE containing normal R (1 byte) + oversized S (33 non-zero bytes, exceeds 32-byte ES256 component)
        $rValue = "\x01";
        $sValue = str_repeat("\x01", 33);
        $derR = "\x02".chr(strlen($rValue)).$rValue;
        $derS = "\x02".chr(strlen($sValue)).$sValue;
        $body = $derR.$derS;
        $der = "\x30".chr(strlen($body)).$body;

        EcdsaSignatureConverter::derToRaw($der, 256);
    }

    #[Test]
    #[TestDox('rawToDer: rejects 128-byte input for ES512 (regression: old code expected 128 instead of 132)')]
    public function raw_to_der_throws_for_old_es512_length(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('exactly 132 bytes');

        // 128 bytes = old incorrect length (512/8 * 2); correct is 132 (ceil(521/8) * 2)
        EcdsaSignatureConverter::rawToDer(str_repeat("\x01", 128), 512);
    }

    #[Test]
    #[TestDox('rawToDer: rejects wrong-length input for ES384')]
    public function raw_to_der_throws_for_wrong_es384_length(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('exactly 96 bytes');

        EcdsaSignatureConverter::rawToDer(str_repeat("\x01", 64), 384);
    }

    /**
     * @return array<string, array{int, string, int, int}>
     */
    public static function keySizeProvider(): array
    {
        return [
            'ES256 (P-256)' => [256, 'prime256v1', OPENSSL_ALGO_SHA256, 64],
            'ES384 (P-384)' => [384, 'secp384r1', OPENSSL_ALGO_SHA384, 96],
            'ES512 (P-521)' => [512, 'secp521r1', OPENSSL_ALGO_SHA512, 132],
        ];
    }

    #[Test]
    #[TestDox('Round-trip: multiple signatures across key sizes')]
    #[DataProvider('keySizeProvider')]
    public function round_trip_per_key_size(int $keySize, string $curve, int $algo, int $rawLen): void
    {
        $ecKey = self::createEcKey($curve);
        $details = openssl_pkey_get_details($ecKey);
        $publicKey = openssl_pkey_get_public($details['key']);

        for ($i = 0; $i < 5; $i++) {
            $payload = "payload-{$keySize}-{$i}";
            $this->assertTrue(openssl_sign($payload, $der, $ecKey, $algo));

            $raw = EcdsaSignatureConverter::derToRaw($der, $keySize);
            $this->assertSame($rawLen, strlen($raw));

            $derAgain = EcdsaSignatureConverter::rawToDer($raw, $keySize);
            $this->assertSame(1, openssl_verify($payload, $derAgain, $publicKey, $algo));
        }
    }
}
