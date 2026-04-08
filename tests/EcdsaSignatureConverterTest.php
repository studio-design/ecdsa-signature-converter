<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature\Tests;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use StudioDesign\EcdsaSignature\EcdsaSignatureConverter;

final class EcdsaSignatureConverterTest extends TestCase
{
    /**
     * Create an EC P-256 key compatible with both PHP 8.2/8.3 and PHP 8.4+.
     */
    private static function createEcKey(): OpenSSLAsymmetricKey
    {
        // PHP 8.4 changed the openssl_pkey_new() config format for EC keys
        $key = openssl_pkey_new([
            'ec'               => ['curve_name' => 'prime256v1'],
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);

        if ($key === false) {
            // Fallback for PHP 8.2/8.3
            $key = openssl_pkey_new([
                'curve_name'       => 'prime256v1',
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
    #[TestDox('derToRaw: ES256 DER signature is converted to 64-byte raw format')]
    public function der_to_raw_converts_es256(): void
    {
        $ecKey = self::createEcKey();

        openssl_sign('test-payload', $der, $ecKey, OPENSSL_ALGO_SHA256);

        $raw = EcdsaSignatureConverter::derToRaw($der, 256);

        $this->assertSame(64, strlen($raw));
    }

    #[Test]
    #[TestDox('derToRaw: converted raw signature is verifiable with OpenSSL')]
    public function der_to_raw_round_trip_is_verifiable(): void
    {
        $ecKey = self::createEcKey();
        $details = openssl_pkey_get_details($ecKey);
        $publicKey = openssl_pkey_get_public($details['key']);

        $payload = 'test-payload';
        openssl_sign($payload, $der, $ecKey, OPENSSL_ALGO_SHA256);

        $raw = EcdsaSignatureConverter::derToRaw($der, 256);
        $derAgain = EcdsaSignatureConverter::rawToDer($raw, 256);

        $result = openssl_verify($payload, $derAgain, $publicKey, OPENSSL_ALGO_SHA256);
        $this->assertSame(1, $result);
    }

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
    #[TestDox('derToRaw: throws for trailing data after R and S')]
    public function der_to_raw_throws_for_trailing_data(): void
    {
        $ecKey = self::createEcKey();

        openssl_sign('test-payload', $der, $ecKey, OPENSSL_ALGO_SHA256);

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

        // SEQUENCE(len=6) -> INTEGER with long-form length claiming 5 bytes but only 4 remain
        EcdsaSignatureConverter::derToRaw("\x30\x06\x02\x85\x00\x00\x00\x00", 256);
    }

    // ---------------------------------------------------------------
    // rawToDer
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('rawToDer: converts 64-byte raw ES256 signature to valid DER')]
    public function raw_to_der_converts_es256(): void
    {
        $ecKey = self::createEcKey();
        $details = openssl_pkey_get_details($ecKey);
        $publicKey = openssl_pkey_get_public($details['key']);

        $payload = 'test-payload';
        openssl_sign($payload, $der, $ecKey, OPENSSL_ALGO_SHA256);

        // DER -> raw -> DER should produce a verifiable signature
        $raw = EcdsaSignatureConverter::derToRaw($der, 256);
        $derAgain = EcdsaSignatureConverter::rawToDer($raw, 256);

        $this->assertSame(1, openssl_verify($payload, $derAgain, $publicKey, OPENSSL_ALGO_SHA256));
    }

    #[Test]
    #[TestDox('rawToDer: throws for wrong raw signature length')]
    public function raw_to_der_throws_for_wrong_length(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('exactly 64 bytes');

        EcdsaSignatureConverter::rawToDer(str_repeat("\x01", 63), 256);
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
    // Round-trip: multiple iterations
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('Round-trip: DER -> raw -> DER produces identical verification result across multiple signatures')]
    public function round_trip_multiple_signatures(): void
    {
        $ecKey = self::createEcKey();
        $details = openssl_pkey_get_details($ecKey);
        $publicKey = openssl_pkey_get_public($details['key']);

        for ($i = 0; $i < 10; $i++) {
            $payload = "payload-{$i}";
            openssl_sign($payload, $der, $ecKey, OPENSSL_ALGO_SHA256);

            $raw = EcdsaSignatureConverter::derToRaw($der, 256);
            $derAgain = EcdsaSignatureConverter::rawToDer($raw, 256);

            $this->assertSame(64, strlen($raw), "Iteration {$i}: raw should be 64 bytes");
            $this->assertSame(1, openssl_verify($payload, $derAgain, $publicKey, OPENSSL_ALGO_SHA256), "Iteration {$i}: verification failed");
        }
    }
}
