<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\TokenAuth;

use Infocyph\AuthLayer\Support\HasEnumStatusResult;

final readonly class TokenRevocationResult
{
    use HasEnumStatusResult;

    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public TokenRevocationStatus $status,
        public string $familyId,
        public ?string $code = null,
        public array $context = [],
    ) {}

    /**
     * @return list<object>
     */
    protected function successStatuses(): array
    {
        return [TokenRevocationStatus::REVOKED, TokenRevocationStatus::ALREADY_REVOKED];
    }
}
