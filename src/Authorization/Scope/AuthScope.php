<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Scope;

final readonly class AuthScope
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public ?string $tenantId = null,
        public ?string $workspaceId = null,
        public ?string $organizationId = null,
        public array $metadata = [],
    ) {}
}
