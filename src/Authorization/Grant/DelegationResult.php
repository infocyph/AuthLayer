<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Grant;

use Infocyph\AuthLayer\Support\HasEnumStatusResult;

final readonly class DelegationResult
{
    use HasEnumStatusResult;

    /**
     * @param list<AccessGrant> $grants
     * @param array<string, mixed> $context
     */
    public function __construct(
        public DelegationStatus $status,
        public ?AccessGrant $grant = null,
        public array $grants = [],
        public ?string $code = null,
        public array $context = [],
    ) {}

    /**
     * @return list<object>
     */
    protected function successStatuses(): array
    {
        return [DelegationStatus::GRANTED, DelegationStatus::LISTED, DelegationStatus::REVOKED];
    }
}
