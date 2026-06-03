<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Grant;

final readonly class DelegationResult
{
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
    ) {
    }
}
