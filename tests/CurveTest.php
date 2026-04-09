<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature\Tests;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use StudioDesign\EcdsaSignature\Curve;
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
