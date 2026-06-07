<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Passkey;

use Infocyph\AuthLayer\Support\HasEnumStatusResult;

final readonly class PasskeyAuthenticationOutcome
{
    use HasEnumStatusResult;

    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public PasskeyAuthenticationStatus $status,
        public ?PasskeyChallenge $challenge = null,
        public ?PasskeyVerificationResult $verification = null,
        public ?string $code = null,
        public array $context = [],
    ) {}

    /**
     * @return list<object>
     */
    protected function successStatuses(): array
    {
        return [PasskeyAuthenticationStatus::STARTED, PasskeyAuthenticationStatus::VERIFIED];
    }
}
