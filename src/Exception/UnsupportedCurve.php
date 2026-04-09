<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature\Exception;

/**
 * Thrown when a curve identifier (JOSE algorithm name, OpenSSL curve name) is not supported.
 */
final class UnsupportedCurve extends EcdsaSignatureException {}
