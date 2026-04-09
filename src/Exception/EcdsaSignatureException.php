<?php

declare(strict_types=1);

namespace StudioDesign\EcdsaSignature\Exception;

use InvalidArgumentException;

/**
 * Base exception for all ECDSA signature errors.
 *
 * Extends InvalidArgumentException so that existing code catching
 * InvalidArgumentException continues to work without changes.
 */
class EcdsaSignatureException extends InvalidArgumentException {}
