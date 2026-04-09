<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature\Exception;

/**
 * Thrown when R or S is mathematically out of range.
 *
 * ECDSA requires 0 < r, s < n (curve order). This exception covers
 * zero-valued components, values equal to or exceeding the curve order,
 * and DER components that exceed the curve's byte-length limit.
 */
final class InvalidSignatureComponent extends EcdsaSignatureException {}
