<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature\Exception;

/**
 * Thrown when DER-encoded input is structurally malformed.
 *
 * Examples: missing SEQUENCE tag, truncated data, non-minimal length encoding,
 * invalid INTEGER encoding (negative, non-minimal leading zeros).
 */
final class InvalidDerSignature extends EcdsaSignatureException {}
