<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature\Tests;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use StudioDesign\EcdsaSignature\Curve;
use StudioDesign\EcdsaSignature\Exception\EcdsaSignatureException;
use StudioDesign\EcdsaSignature\Exception\UnsupportedCurve;
use ValueError;

final class CurveTest extends TestCase
{
    #[Test]
    #[TestDox('Curve::from resolves valid JOSE key-size integers')]
    public function from_resolves_valid_values(): void
    {
        $this->assertSame(Curve::P256, Curve::from(256));
        $this->assertSame(Curve::P384, Curve::from(384));
        $this->assertSame(Curve::P521, Curve::from(512));
    }

    #[Test]
    #[TestDox('Curve::from throws ValueError for unsupported key size')]
    public function from_throws_for_unsupported_key_size(): void
    {
        $this->expectException(ValueError::class);

        Curve::from(128);
    }

    // ---------------------------------------------------------------
    // fromJoseAlg
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('fromJoseAlg resolves ES256, ES384, ES512')]
    public function from_jose_alg_resolves_valid_algorithms(): void
    {
        $this->assertSame(Curve::P256, Curve::fromJoseAlg('ES256'));
        $this->assertSame(Curve::P384, Curve::fromJoseAlg('ES384'));
        $this->assertSame(Curve::P521, Curve::fromJoseAlg('ES512'));
    }

    #[Test]
    #[TestDox('fromJoseAlg throws UnsupportedCurve for unsupported algorithm')]
    public function from_jose_alg_throws_for_unsupported(): void
    {
        $this->expectException(UnsupportedCurve::class);
        $this->expectExceptionMessage('RS256');

        Curve::fromJoseAlg('RS256');
    }

    #[Test]
    #[TestDox('fromJoseAlg is case-sensitive')]
    public function from_jose_alg_is_case_sensitive(): void
    {
        $this->expectException(UnsupportedCurve::class);

        Curve::fromJoseAlg('es256');
    }

    // ---------------------------------------------------------------
    // fromOpenSslCurveName
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('fromOpenSslCurveName resolves prime256v1, secp384r1, secp521r1')]
    public function from_openssl_curve_name_resolves_valid_names(): void
    {
        $this->assertSame(Curve::P256, Curve::fromOpenSslCurveName('prime256v1'));
        $this->assertSame(Curve::P384, Curve::fromOpenSslCurveName('secp384r1'));
        $this->assertSame(Curve::P521, Curve::fromOpenSslCurveName('secp521r1'));
    }

    #[Test]
    #[TestDox('fromOpenSslCurveName throws UnsupportedCurve for unsupported curve name')]
    public function from_openssl_curve_name_throws_for_unsupported(): void
    {
        $this->expectException(UnsupportedCurve::class);
        $this->expectExceptionMessage('secp256k1');

        Curve::fromOpenSslCurveName('secp256k1');
    }

    #[Test]
    #[TestDox('UnsupportedCurve is catchable as EcdsaSignatureException')]
    public function unsupported_curve_is_catchable_as_base(): void
    {
        $this->expectException(EcdsaSignatureException::class);

        Curve::fromJoseAlg('RS256');
    }

    // ---------------------------------------------------------------
    // joseAlg / openSslCurveName
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('joseAlg returns the JOSE algorithm name')]
    public function jose_alg_returns_correct_names(): void
    {
        $this->assertSame('ES256', Curve::P256->joseAlg());
        $this->assertSame('ES384', Curve::P384->joseAlg());
        $this->assertSame('ES512', Curve::P521->joseAlg());
    }

    #[Test]
    #[TestDox('openSslCurveName returns the OpenSSL curve name')]
    public function openssl_curve_name_returns_correct_names(): void
    {
        $this->assertSame('prime256v1', Curve::P256->openSslCurveName());
        $this->assertSame('secp384r1', Curve::P384->openSslCurveName());
        $this->assertSame('secp521r1', Curve::P521->openSslCurveName());
    }

    #[Test]
    #[TestDox('fromJoseAlg and joseAlg are inverse operations')]
    public function jose_alg_round_trip(): void
    {
        foreach (Curve::cases() as $curve) {
            $this->assertSame($curve, Curve::fromJoseAlg($curve->joseAlg()));
        }
    }

    #[Test]
    #[TestDox('fromOpenSslCurveName and openSslCurveName are inverse operations')]
    public function openssl_curve_name_round_trip(): void
    {
        foreach (Curve::cases() as $curve) {
            $this->assertSame($curve, Curve::fromOpenSslCurveName($curve->openSslCurveName()));
        }
    }

    // ---------------------------------------------------------------
    // componentLength / order
    // ---------------------------------------------------------------

    #[Test]
    #[TestDox('componentLength returns correct byte lengths')]
    public function component_length_returns_correct_values(): void
    {
        $this->assertSame(32, Curve::P256->componentLength());
        $this->assertSame(48, Curve::P384->componentLength());
        $this->assertSame(66, Curve::P521->componentLength());
    }

    #[Test]
    #[TestDox('order returns binary string matching componentLength')]
    public function order_length_matches_component_length(): void
    {
        foreach (Curve::cases() as $curve) {
            $this->assertSame(
                $curve->componentLength(),
                strlen($curve->order()),
                "Curve {$curve->name} order length mismatch",
            );
        }
    }

    #[Test]
    #[TestDox('order returns known curve order constants')]
    public function order_returns_known_constants(): void
    {
        $this->assertSame(
            'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
            bin2hex(Curve::P256->order()),
        );

        $this->assertSame(
            'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
            bin2hex(Curve::P384->order()),
        );

        $this->assertSame(
            '01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409',
            bin2hex(Curve::P521->order()),
        );
    }
}
