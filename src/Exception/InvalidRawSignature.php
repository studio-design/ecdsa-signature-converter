<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature\Exception;

/**
 * Thrown when a JWS raw (R||S) signature has an invalid byte length.
 */
final class InvalidRawSignature extends EcdsaSignatureException {}
