<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature\Tests;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use StudioDesign\EcdsaSignature\Curve;
use StudioDesign\EcdsaSignature\EcdsaSignature;
use StudioDesign\EcdsaSignature\Exception\EcdsaSignatureException;
use StudioDesign\EcdsaSignature\Exception\InvalidDerSignature;
use StudioDesign\EcdsaSignature\Exception\InvalidRawSignature;
use StudioDesign\EcdsaSignature\Exception\InvalidSignatureComponent;

final class EcdsaSignatureTest extends TestCase
{
    /**
     * Build a simple DER SEQUENCE containing two INTEGER TLVs from raw R and S values.
     *
     * Only supports short-form DER length encoding (each component's byte length must be < 128).
     * Intended for crafting test inputs, not production use.
     */
    private static function buildSimpleDer(string $rValue, string $sValue): string
    {
        $derR = "\x02".chr(strlen($rValue)).$rValue;
        $derS = "\x02".chr(strlen($sValue)).$sValue;
        $body = $derR.$derS;

        return "\x30".chr(strlen($body)).$body;
    }

    /**
     * Create an EC key for the given curve, compatible with both PHP 8.2/8.3 and PHP 8.4+.
     */
    private static function createEcKey(string $curve = 'prime256v1'): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new([
            'ec'               => ['curve_name' => $curve],
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);

        if ($key === false) {
            $firstError = openssl_error_string() ?: 'unknown error';
            $key = openssl_pkey_new([
                'curve_name'       => $curve,
                'private_key_type' => OPENSSL_KEYTYPE_EC,
            ]);
        }

        if (! $key instanceof OpenSSLAsymmetricKey) {
            $error = openssl_error_string() ?: 'unknown error';
            self::fail("Failed to create EC key for curve '{$curve}': {$error}".(isset($firstError) ? " (first attempt: {$firstError})" : ''));
        }

        return $key;
    }

    // ---------------------------------------------------------------
    // Exception hierarchy: backward compatibility
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('InvalidDerSignature is catchable as InvalidArgumentException')]
    public function invalid_der_is_catchable_as_invalid_argument_exception(): void
    {
        $this->expectException(InvalidArgumentException::class);

        EcdsaSignature::fromDer("\x30\x00", Curve::P256);
    }

    #[Test]
    #[TestDox('InvalidRawSignature is catchable as InvalidArgumentException')]
    public function invalid_raw_is_catchable_as_invalid_argument_exception(): void
    {
        $this->expectException(InvalidArgumentException::class);

        EcdsaSignature::fromRaw('short', Curve::P256);
    }

    #[Test]
    #[TestDox('InvalidSignatureComponent is catchable as InvalidArgumentException')]
    public function invalid_component_is_catchable_as_invalid_argument_exception(): void
    {
        $this->expectException(InvalidArgumentException::class);

        EcdsaSignature::fromRaw(str_repeat("\x00", 64), Curve::P256);
    }

    #[Test]
    #[TestDox('All signature exceptions are catchable as EcdsaSignatureException')]
    public function all_exceptions_catchable_as_base(): void
    {
        $caught = 0;

        try {
            EcdsaSignature::fromDer("\x30\x00", Curve::P256);
        } catch (EcdsaSignatureException) {
            $caught++;
        }

        try {
            EcdsaSignature::fromRaw('short', Curve::P256);
        } catch (EcdsaSignatureException) {
            $caught++;
        }

        try {
            EcdsaSignature::fromRaw(str_repeat("\x00", 64), Curve::P256);
        } catch (EcdsaSignatureException) {
            $caught++;
        }

        $this->assertSame(3, $caught);
    }

    // ---------------------------------------------------------------
    // fromDer: DER parsing errors
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature for too-short DER data')]
    public function from_der_throws_for_short_der(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('too short');

        EcdsaSignature::fromDer("\x30\x00", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature when DER does not start with SEQUENCE tag')]
    public function from_der_throws_for_invalid_sequence_tag(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('SEQUENCE tag');

        EcdsaSignature::fromDer("\x02\x01\x00\x02\x01\x00\x00\x00", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature for trailing data after SEQUENCE')]
    public function from_der_throws_for_trailing_data(): void
    {
        $ecKey = self::createEcKey();

        $this->assertTrue(openssl_sign('test-payload', $der, $ecKey, OPENSSL_ALGO_SHA256), 'openssl_sign failed: '.(openssl_error_string() ?: 'unknown error'));

        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('trailing data');

        EcdsaSignature::fromDer($der."\x00", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature for truncated multi-byte length field')]
    public function from_der_throws_for_truncated_multi_byte_length(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('multi-byte length field is incomplete');

        EcdsaSignature::fromDer("\x30\x06\x02\x01\x01\x02\x83\x00", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature when R or S component has non-INTEGER tag')]
    public function from_der_throws_for_non_integer_tag(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('must be INTEGERs');

        EcdsaSignature::fromDer("\x30\x06\x04\x01\x01\x02\x01\x01", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature when S component has non-INTEGER tag')]
    public function from_der_throws_for_non_integer_s_tag(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('must be INTEGERs');

        EcdsaSignature::fromDer("\x30\x06\x02\x01\x01\x04\x01\x01", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature for empty string input')]
    public function from_der_throws_for_empty_input(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('too short');

        EcdsaSignature::fromDer('', Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature when SEQUENCE contains only one INTEGER')]
    public function from_der_throws_for_single_component(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('must contain two INTEGER components');

        EcdsaSignature::fromDer("\x30\x06\x02\x04\x00\x00\x00\x01", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature when SEQUENCE content length does not match parsed children')]
    public function from_der_throws_for_sequence_length_mismatch(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('SEQUENCE content length');

        EcdsaSignature::fromDer("\x30\x08\x02\x01\x01\x02\x01\x01\x00\x00", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature for negative DER INTEGER R')]
    public function from_der_throws_for_negative_r(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('R component is negative');

        EcdsaSignature::fromDer("\x30\x06\x02\x01\xFF\x02\x01\x01", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature for negative DER INTEGER S')]
    public function from_der_throws_for_negative_s(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('S component is negative');

        EcdsaSignature::fromDer("\x30\x06\x02\x01\x01\x02\x01\xFF", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: rejects non-minimal INTEGER encoding in R')]
    public function from_der_rejects_non_minimal_r(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('non-minimal encoding');

        EcdsaSignature::fromDer("\x30\x08\x02\x03\x00\x00\x01\x02\x01\x01", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: rejects non-minimal INTEGER encoding in S')]
    public function from_der_rejects_non_minimal_s(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('non-minimal encoding');

        EcdsaSignature::fromDer("\x30\x07\x02\x01\x01\x02\x02\x00\x01", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidSignatureComponent when DER INTEGER value exceeds component length (R)')]
    public function from_der_throws_for_oversized_r(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('R value (33 bytes) exceeds');

        $der = self::buildSimpleDer(str_repeat("\x01", 33), "\x01");

        EcdsaSignature::fromDer($der, Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidSignatureComponent when DER INTEGER value exceeds component length (S)')]
    public function from_der_throws_for_oversized_s(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('S value (33 bytes) exceeds');

        $der = self::buildSimpleDer("\x01", str_repeat("\x01", 33));

        EcdsaSignature::fromDer($der, Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature when DER INTEGER has zero length')]
    public function from_der_throws_for_zero_length_integer(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('at least one content octet');

        EcdsaSignature::fromDer("\x30\x08\x02\x00\x02\x04\x00\x00\x00\x01", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature when DER INTEGER S has zero length')]
    public function from_der_throws_for_zero_length_s_integer(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('at least one content octet');

        EcdsaSignature::fromDer("\x30\x08\x02\x04\x00\x00\x00\x01\x02\x00", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature when DER INTEGER value extends beyond data length')]
    public function from_der_throws_for_truncated_value(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('value extends beyond data length');

        EcdsaSignature::fromDer("\x30\x06\x02\x05\x01\x02\x03\x04", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature when second INTEGER has missing length byte')]
    public function from_der_throws_for_missing_length_byte(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('missing length byte');

        EcdsaSignature::fromDer("\x30\x06\x02\x03\x00\x00\x01\x02", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature for DER indefinite-length encoding')]
    public function from_der_throws_for_indefinite_length(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('indefinite-length');

        EcdsaSignature::fromDer("\x30\x80\x02\x01\x01\x02\x01\x01", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature for non-Universal class tag')]
    public function from_der_throws_for_non_universal_class_tag(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('non-Universal class tag');

        EcdsaSignature::fromDer("\x30\x06\xA0\x01\x01\x02\x01\x01", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature for application class tag')]
    public function from_der_throws_for_application_class_tag(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('non-Universal class tag');

        EcdsaSignature::fromDer("\x30\x06\x42\x01\x01\x02\x01\x01", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature for multi-byte ASN.1 tag number')]
    public function from_der_throws_for_multi_byte_tag(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('multi-byte tag');

        EcdsaSignature::fromDer("\x30\x06\x1F\x01\x01\x02\x01\x01", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature for non-minimal DER length encoding')]
    public function from_der_throws_for_non_minimal_length(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('non-minimal');

        EcdsaSignature::fromDer("\x30\x81\x06\x02\x01\x01\x02\x01\x01", Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature for non-minimal multi-byte DER length encoding')]
    public function from_der_throws_for_non_minimal_multi_byte_length(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('more octets than necessary');

        $secondIntValue = str_repeat("\x00", 128);
        $secondInt = "\x02\x82\x00\x80".$secondIntValue;
        $firstInt = "\x02\x01\x01";
        $body = $firstInt.$secondInt;
        $der = "\x30\x81\x87".$body;

        EcdsaSignature::fromDer($der, Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: throws InvalidDerSignature when DER length field exceeds 4 bytes')]
    public function from_der_throws_for_excessive_length_bytes(): void
    {
        $this->expectException(InvalidDerSignature::class);
        $this->expectExceptionMessage('exceeds 4 bytes');

        EcdsaSignature::fromDer("\x30\x0B\x02\x85\x00\x00\x00\x00\x01\x02\x01\x01\x01", Curve::P256);
    }

    // ---------------------------------------------------------------
    // fromDer: mathematical validation (0 < r,s < n)
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('fromDer: rejects R=0 with InvalidSignatureComponent')]
    public function from_der_rejects_zero_r(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('R component must be greater than zero');

        // SEQUENCE { INTEGER(0x00), INTEGER(0x01) }
        $der = "\x30\x06\x02\x01\x00\x02\x01\x01";

        EcdsaSignature::fromDer($der, Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: rejects S=0 with InvalidSignatureComponent')]
    public function from_der_rejects_zero_s(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('S component must be greater than zero');

        // SEQUENCE { INTEGER(0x01), INTEGER(0x00) }
        $der = "\x30\x06\x02\x01\x01\x02\x01\x00";

        EcdsaSignature::fromDer($der, Curve::P256);
    }

    #[Test]
    #[TestDox('fromDer: rejects ES512 component exceeding curve order')]
    public function from_der_rejects_es512_exceeding_order(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('must be less than the curve order');

        // R = 0x00 (sign pad) + 0x82 + 65 zero bytes = 67-byte DER INTEGER value
        // After stripping: 66 bytes starting with 0x82 → exceeds P-521 order (starts with 0x01)
        $rValue = "\x00\x82".str_repeat("\x00", 65);
        $sValue = "\x01";
        $der = self::buildSimpleDer($rValue, $sValue);

        EcdsaSignature::fromDer($der, Curve::P521);
    }

    // ---------------------------------------------------------------
    // fromRaw: input validation
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('fromRaw: throws InvalidRawSignature for too-short raw signature')]
    public function from_raw_throws_for_short_raw(): void
    {
        $this->expectException(InvalidRawSignature::class);
        $this->expectExceptionMessage('exactly 64 bytes');

        EcdsaSignature::fromRaw(str_repeat("\x01", 63), Curve::P256);
    }

    #[Test]
    #[TestDox('fromRaw: throws InvalidRawSignature for too-long raw signature')]
    public function from_raw_throws_for_long_raw(): void
    {
        $this->expectException(InvalidRawSignature::class);
        $this->expectExceptionMessage('exactly 64 bytes');

        EcdsaSignature::fromRaw(str_repeat("\x01", 65), Curve::P256);
    }

    #[Test]
    #[TestDox('fromRaw: rejects 128-byte input for ES512 (must be 132)')]
    public function from_raw_rejects_old_es512_length(): void
    {
        $this->expectException(InvalidRawSignature::class);
        $this->expectExceptionMessage('exactly 132 bytes');

        EcdsaSignature::fromRaw(str_repeat("\x01", 128), Curve::P521);
    }

    #[Test]
    #[TestDox('fromRaw: rejects wrong-length input for ES384')]
    public function from_raw_rejects_wrong_es384_length(): void
    {
        $this->expectException(InvalidRawSignature::class);
        $this->expectExceptionMessage('exactly 96 bytes');

        EcdsaSignature::fromRaw(str_repeat("\x01", 64), Curve::P384);
    }

    // ---------------------------------------------------------------
    // fromRaw: mathematical validation (0 < r,s < n)
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('fromRaw: rejects R=0 with InvalidSignatureComponent')]
    public function from_raw_rejects_zero_r(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('R component must be greater than zero');

        $r = str_repeat("\x00", 32);
        $s = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);

        EcdsaSignature::fromRaw($r.$s, Curve::P256);
    }

    #[Test]
    #[TestDox('fromRaw: rejects S=0 with InvalidSignatureComponent')]
    public function from_raw_rejects_zero_s(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('S component must be greater than zero');

        $r = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $s = str_repeat("\x00", 32);

        EcdsaSignature::fromRaw($r.$s, Curve::P256);
    }

    #[Test]
    #[TestDox('fromRaw: rejects both R and S as zero')]
    public function from_raw_rejects_both_zero(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('must be greater than zero');

        EcdsaSignature::fromRaw(str_repeat("\x00", 64), Curve::P256);
    }

    #[Test]
    #[TestDox('fromRaw: rejects R exactly equal to curve order')]
    public function from_raw_rejects_r_equal_to_order(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('must be less than the curve order');

        $order = Curve::P256->order();
        $s = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);

        EcdsaSignature::fromRaw($order.$s, Curve::P256);
    }

    #[Test]
    #[TestDox('fromRaw: rejects S exactly equal to curve order')]
    public function from_raw_rejects_s_equal_to_order(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('must be less than the curve order');

        $r = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $order = Curve::P256->order();

        EcdsaSignature::fromRaw($r.$order, Curve::P256);
    }

    #[Test]
    #[TestDox('fromRaw: rejects R exceeding curve order (all 0xFF for P-256)')]
    public function from_raw_rejects_r_exceeding_order(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('must be less than the curve order');

        $r = str_repeat("\xFF", 32);
        $s = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);

        EcdsaSignature::fromRaw($r.$s, Curve::P256);
    }

    #[Test]
    #[TestDox('fromRaw: accepts R equal to order minus one')]
    public function from_raw_accepts_order_minus_one(): void
    {
        $order = Curve::P256->order();

        // Subtract 1 from the order (big-endian binary decrement)
        $nMinus1 = $order;
        for ($i = strlen($nMinus1) - 1; $i >= 0; $i--) {
            $byte = ord($nMinus1[$i]);
            if ($byte > 0) {
                $nMinus1[$i] = chr($byte - 1);
                break;
            }
            $nMinus1[$i] = "\xFF";
        }

        $s = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);

        $sig = EcdsaSignature::fromRaw($nMinus1.$s, Curve::P256);

        $this->assertSame($nMinus1, $sig->r());
    }

    #[Test]
    #[TestDox('fromRaw: rejects ES512 R exceeding curve order')]
    public function from_raw_rejects_es512_r_exceeding_order(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('must be less than the curve order');

        // R starts with 0x02 → exceeds P-521 order (starts with 0x01)
        $r = "\x02".str_repeat("\x00", 65);
        $s = str_pad("\x01", 66, "\x00", STR_PAD_LEFT);

        EcdsaSignature::fromRaw($r.$s, Curve::P521);
    }

    #[Test]
    #[TestDox('fromRaw: rejects ES512 S exceeding curve order')]
    public function from_raw_rejects_es512_s_exceeding_order(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('must be less than the curve order');

        $r = str_pad("\x01", 66, "\x00", STR_PAD_LEFT);
        $s = str_repeat("\xFF", 66);

        EcdsaSignature::fromRaw($r.$s, Curve::P521);
    }

    #[Test]
    #[TestDox('fromRaw: rejects ES384 zero components')]
    public function from_raw_rejects_es384_zero(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('must be greater than zero');

        EcdsaSignature::fromRaw(str_repeat("\x00", 96), Curve::P384);
    }

    #[Test]
    #[TestDox('fromRaw: rejects ES384 all-0xFF (exceeds order)')]
    public function from_raw_rejects_es384_all_ff(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('must be less than the curve order');

        $r = str_repeat("\xFF", 48);
        $s = str_pad("\x01", 48, "\x00", STR_PAD_LEFT);

        EcdsaSignature::fromRaw($r.$s, Curve::P384);
    }

    #[Test]
    #[TestDox('fromRaw: rejects ES512 zero components')]
    public function from_raw_rejects_es512_zero(): void
    {
        $this->expectException(InvalidSignatureComponent::class);
        $this->expectExceptionMessage('must be greater than zero');

        EcdsaSignature::fromRaw(str_repeat("\x00", 132), Curve::P521);
    }

    // ---------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('r(), s(), curve() return correct values')]
    public function accessors_return_correct_values(): void
    {
        $r = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $s = str_pad("\x02", 32, "\x00", STR_PAD_LEFT);
        $raw = $r.$s;

        $sig = EcdsaSignature::fromRaw($raw, Curve::P256);

        $this->assertSame($r, $sig->r());
        $this->assertSame($s, $sig->s());
        $this->assertSame(Curve::P256, $sig->curve());
    }

    #[Test]
    #[TestDox('fromDer: accessors return correct values after DER parsing')]
    public function from_der_accessors(): void
    {
        // R=1, S=2
        $der = "\x30\x06\x02\x01\x01\x02\x01\x02";
        $sig = EcdsaSignature::fromDer($der, Curve::P256);

        $this->assertSame(str_pad("\x01", 32, "\x00", STR_PAD_LEFT), $sig->r());
        $this->assertSame(str_pad("\x02", 32, "\x00", STR_PAD_LEFT), $sig->s());
        $this->assertSame(Curve::P256, $sig->curve());
    }

    // ---------------------------------------------------------------
    // Known vectors (conversion)
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('fromDer: converts known DER bytes to exact raw bytes')]
    public function from_der_known_vector(): void
    {
        // R=1, S=2
        $der = "\x30\x06\x02\x01\x01\x02\x01\x02";
        $expectedRaw = str_pad("\x01", 32, "\x00", STR_PAD_LEFT).str_pad("\x02", 32, "\x00", STR_PAD_LEFT);

        $this->assertSame($expectedRaw, EcdsaSignature::fromDer($der, Curve::P256)->toRaw());
    }

    #[Test]
    #[TestDox('fromRaw: converts known raw bytes to exact DER bytes')]
    public function from_raw_known_vector(): void
    {
        // R=1, S=2
        $raw = str_pad("\x01", 32, "\x00", STR_PAD_LEFT).str_pad("\x02", 32, "\x00", STR_PAD_LEFT);
        $expectedDer = "\x30\x06\x02\x01\x01\x02\x01\x02";

        $this->assertSame($expectedDer, EcdsaSignature::fromRaw($raw, Curve::P256)->toDer());
    }

    #[Test]
    #[TestDox('fromDer: accepts valid sign-padding (0x00 before byte with high bit set)')]
    public function from_der_accepts_valid_sign_padding(): void
    {
        // SEQUENCE { INTEGER(0x00 0x80), INTEGER(0x01) }
        $der = "\x30\x07\x02\x02\x00\x80\x02\x01\x01";

        $sig = EcdsaSignature::fromDer($der, Curve::P256);

        $this->assertSame(64, strlen($sig->toRaw()));
        $this->assertSame(str_pad("\x80", 32, "\x00", STR_PAD_LEFT), $sig->r());
        $this->assertSame(str_pad("\x01", 32, "\x00", STR_PAD_LEFT), $sig->s());
    }

    #[Test]
    #[TestDox('fromRaw: output starts with SEQUENCE tag')]
    public function from_raw_to_der_starts_with_sequence(): void
    {
        $raw = str_repeat("\x01", 64);
        $der = EcdsaSignature::fromRaw($raw, Curve::P256)->toDer();

        $this->assertSame(0x30, ord($der[0]));
    }

    // ---------------------------------------------------------------
    // Edge cases: high-bit R (needs sign padding in DER)
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('fromRaw: known vector with sign-padded R (high bit set, valid value)')]
    public function from_raw_sign_padded_r(): void
    {
        // R = 0x80 + 31 zero bytes (value < P-256 order, high bit set → needs DER sign padding)
        $r = "\x80".str_repeat("\x00", 31);
        $s = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $raw = $r.$s;

        // DER R: INTEGER(33) 0x00 + 0x80 + 31*0x00, DER S: INTEGER(1) 0x01
        $expectedDer = "\x30\x26"
            ."\x02\x21\x00\x80".str_repeat("\x00", 31)
            ."\x02\x01\x01";

        $this->assertSame($expectedDer, EcdsaSignature::fromRaw($raw, Curve::P256)->toDer());
    }

    #[Test]
    #[TestDox('fromRaw: handles R with high bit set (round-trip)')]
    public function from_raw_high_bit_r_round_trip(): void
    {
        // R = 0x80 + 31 zero bytes (valid, needs sign padding in DER)
        $r = "\x80".str_repeat("\x00", 31);
        $s = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $raw = $r.$s;

        $sig = EcdsaSignature::fromRaw($raw, Curve::P256);
        $rawAgain = EcdsaSignature::fromDer($sig->toDer(), Curve::P256)->toRaw();

        $this->assertSame($raw, $rawAgain);
    }

    // ---------------------------------------------------------------
    // Edge cases: minimum values
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('fromRaw: handles minimum non-zero R and S (value = 1)')]
    public function from_raw_min_values(): void
    {
        $r = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $s = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $raw = $r.$s;

        $rawAgain = EcdsaSignature::fromDer(
            EcdsaSignature::fromRaw($raw, Curve::P256)->toDer(),
            Curve::P256,
        )->toRaw();

        $this->assertSame($raw, $rawAgain);
    }

    #[Test]
    #[TestDox('fromRaw: ES384 minimum non-zero values round-trip')]
    public function from_raw_es384_min_values(): void
    {
        $r = str_pad("\x01", 48, "\x00", STR_PAD_LEFT);
        $s = str_pad("\x01", 48, "\x00", STR_PAD_LEFT);
        $raw = $r.$s;

        $rawAgain = EcdsaSignature::fromDer(
            EcdsaSignature::fromRaw($raw, Curve::P384)->toDer(),
            Curve::P384,
        )->toRaw();

        $this->assertSame($raw, $rawAgain);
    }

    #[Test]
    #[TestDox('fromRaw: ES512 minimum non-zero values round-trip')]
    public function from_raw_es512_min_values(): void
    {
        $r = str_pad("\x01", 66, "\x00", STR_PAD_LEFT);
        $s = str_pad("\x01", 66, "\x00", STR_PAD_LEFT);
        $raw = $r.$s;

        $rawAgain = EcdsaSignature::fromDer(
            EcdsaSignature::fromRaw($raw, Curve::P521)->toDer(),
            Curve::P521,
        )->toRaw();

        $this->assertSame($raw, $rawAgain);
    }

    // ---------------------------------------------------------------
    // Edge cases: ES384 high-bit R
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('fromRaw: ES384 handles high-bit R (valid value, needs sign padding)')]
    public function from_raw_es384_high_bit_r(): void
    {
        // R = 0x80 + 47 zero bytes (valid for P-384, needs sign padding in DER)
        $r = "\x80".str_repeat("\x00", 47);
        $s = str_pad("\x01", 48, "\x00", STR_PAD_LEFT);
        $raw = $r.$s;

        $rawAgain = EcdsaSignature::fromDer(
            EcdsaSignature::fromRaw($raw, Curve::P384)->toDer(),
            Curve::P384,
        )->toRaw();

        $this->assertSame($raw, $rawAgain);
    }

    // ---------------------------------------------------------------
    // Edge cases: ES512 long-form DER SEQUENCE length
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('fromRaw: ES512 large values trigger long-form DER SEQUENCE length encoding')]
    public function from_raw_es512_long_form_length(): void
    {
        // ES512: R and S = 0x01 + 65 zero bytes (valid P-521 values)
        // DER INTEGER: no sign-padding needed (0x01 < 0x80) → tag(1) + len(1) + value(66) = 68 bytes each
        // SEQUENCE body = 136 bytes ≥ 128 → long-form length encoding
        $component = "\x01".str_repeat("\x00", 65);
        $raw = $component.$component;

        $der = EcdsaSignature::fromRaw($raw, Curve::P521)->toDer();

        // Verify long-form length: 0x30 0x81 0x88 (SEQUENCE, 1-byte long-form, len=136)
        $this->assertSame(0x30, ord($der[0]));
        $this->assertSame(0x81, ord($der[1]));
        $this->assertSame(136, ord($der[2]));

        $rawAgain = EcdsaSignature::fromDer($der, Curve::P521)->toRaw();
        $this->assertSame($raw, $rawAgain);
    }

    // ---------------------------------------------------------------
    // Edge cases: ES512 boundary values
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('fromDer: accepts ES512 component at valid boundary (first byte 0x01)')]
    public function from_der_accepts_es512_valid_boundary(): void
    {
        // R = 0x01 followed by 65 zero bytes — valid P-521 (well below order)
        $rValue = "\x01".str_repeat("\x00", 65);
        $sValue = "\x01";
        $der = self::buildSimpleDer($rValue, $sValue);

        $sig = EcdsaSignature::fromDer($der, Curve::P521);

        $this->assertSame(132, strlen($sig->toRaw()));
        $this->assertSame("\x01".str_repeat("\x00", 65), $sig->r());
    }

    #[Test]
    #[TestDox('fromRaw: accepts ES512 component at valid boundary (first byte 0x01)')]
    public function from_raw_accepts_es512_valid_boundary(): void
    {
        $r = "\x01".str_repeat("\x00", 65);
        $s = str_pad("\x01", 66, "\x00", STR_PAD_LEFT);
        $raw = $r.$s;

        $rawAgain = EcdsaSignature::fromDer(
            EcdsaSignature::fromRaw($raw, Curve::P521)->toDer(),
            Curve::P521,
        )->toRaw();

        $this->assertSame($raw, $rawAgain);
    }

    // ---------------------------------------------------------------
    // Round-trip with OpenSSL
    // ---------------------------------------------------------------

    /**
     * @return array<string, array{Curve, string, int, int}>
     */
    public static function curveProvider(): array
    {
        return [
            'ES256 (P-256)' => [Curve::P256, 'prime256v1', OPENSSL_ALGO_SHA256, 64],
            'ES384 (P-384)' => [Curve::P384, 'secp384r1', OPENSSL_ALGO_SHA384, 96],
            'ES512 (P-521)' => [Curve::P521, 'secp521r1', OPENSSL_ALGO_SHA512, 132],
        ];
    }

    #[Test]
    #[TestDox('Round-trip: multiple signatures across key sizes')]
    #[DataProvider('curveProvider')]
    public function round_trip_per_curve(Curve $curve, string $openSslCurve, int $algo, int $rawLen): void
    {
        $ecKey = self::createEcKey($openSslCurve);
        $details = openssl_pkey_get_details($ecKey);
        $this->assertIsArray($details, 'Failed to get key details');
        $publicKey = openssl_pkey_get_public($details['key']);
        $this->assertNotFalse($publicKey, 'Failed to extract public key');

        for ($i = 0; $i < 5; $i++) {
            $payload = "payload-{$curve->value}-{$i}";
            $this->assertTrue(openssl_sign($payload, $der, $ecKey, $algo), 'openssl_sign failed: '.(openssl_error_string() ?: 'unknown error'));

            $sig = EcdsaSignature::fromDer($der, $curve);
            $raw = $sig->toRaw();
            $this->assertSame($rawLen, strlen($raw));

            $derAgain = EcdsaSignature::fromRaw($raw, $curve)->toDer();
            $this->assertSame(1, openssl_verify($payload, $derAgain, $publicKey, $algo));
        }
    }

    // ---------------------------------------------------------------
    // Round-trip with OpenSSL using Curve helper methods
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('Round-trip: Curve::fromJoseAlg and openSslCurveName work end-to-end')]
    public function round_trip_using_curve_helpers(): void
    {
        $curve = Curve::fromJoseAlg('ES256');
        $ecKey = self::createEcKey($curve->openSslCurveName());

        $this->assertTrue(openssl_sign('test', $der, $ecKey, OPENSSL_ALGO_SHA256));

        $sig = EcdsaSignature::fromDer($der, $curve);
        $this->assertSame(64, strlen($sig->toRaw()));
        $this->assertSame('ES256', $sig->curve()->joseAlg());
    }
}
