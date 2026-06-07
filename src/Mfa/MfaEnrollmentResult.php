<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Mfa;

use Infocyph\AuthLayer\Support\HasEnumStatusResult;

final readonly class MfaEnrollmentResult
{
    use HasEnumStatusResult;

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
    ) {}

    /**
     * @return list<object>
     */
    protected function successStatuses(): array
    {
        return [MfaStatus::ENROLLED, MfaStatus::ACTIVATED, MfaStatus::REMOVED];
    }
}
