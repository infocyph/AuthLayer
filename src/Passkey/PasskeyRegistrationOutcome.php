<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Passkey;

use Infocyph\AuthLayer\Support\HasEnumStatusResult;

final readonly class PasskeyRegistrationOutcome
{
    use HasEnumStatusResult;

    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public PasskeyRegistrationStatus $status,
        public ?PasskeyChallenge $challenge = null,
        public ?PasskeyCredential $credential = null,
        public ?string $code = null,
        public array $context = [],
    ) {}

    /**
     * @return list<object>
     */
    protected function successStatuses(): array
    {
        return [PasskeyRegistrationStatus::STARTED, PasskeyRegistrationStatus::REGISTERED];
    }
}
