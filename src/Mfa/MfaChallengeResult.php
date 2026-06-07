<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Mfa;

use Infocyph\AuthLayer\Support\HasEnumStatusResult;

final readonly class MfaChallengeResult
{
    use HasEnumStatusResult;

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
    ) {}

    /**
     * @return list<object>
     */
    protected function successStatuses(): array
    {
        return [
            MfaStatus::CHALLENGE_ISSUED,
            MfaStatus::VERIFIED,
            MfaStatus::RECOVERY_CODE_VERIFIED,
        ];
    }
}
