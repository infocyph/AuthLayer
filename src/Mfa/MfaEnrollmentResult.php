<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Mfa;

final readonly class MfaEnrollmentResult
{
    /**
     * @param list<string> $recoveryCodes
     * @param array<string, mixed> $context
     */
    public function __construct(
        public MfaStatus $status,
        public ?MfaFactor $factor = null,
        public array $recoveryCodes = [],
        public ?string $code = null,
        public array $context = [],
    ) {
    }
}
