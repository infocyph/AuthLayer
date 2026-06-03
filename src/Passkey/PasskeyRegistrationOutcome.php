<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Passkey;

final readonly class PasskeyRegistrationOutcome
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public PasskeyRegistrationStatus $status,
        public ?PasskeyChallenge $challenge = null,
        public ?PasskeyCredential $credential = null,
        public ?string $code = null,
        public array $context = [],
    ) {
    }
}
