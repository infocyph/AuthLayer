<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Mfa;

final readonly class MfaChallengeResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public MfaStatus $status,
        public ?MfaChallenge $challenge = null,
        public ?MfaVerificationResult $verification = null,
        public ?MfaFactor $factor = null,
        public ?string $code = null,
        public array $context = [],
    ) {
    }
}
