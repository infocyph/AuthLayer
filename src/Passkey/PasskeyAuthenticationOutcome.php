<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Passkey;

final readonly class PasskeyAuthenticationOutcome
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public PasskeyAuthenticationStatus $status,
        public ?PasskeyChallenge $challenge = null,
        public ?PasskeyVerificationResult $verification = null,
        public ?string $code = null,
        public array $context = [],
    ) {
    }
}
