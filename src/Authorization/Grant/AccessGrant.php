<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Grant;

final readonly class AccessGrant
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public string $id,
        public string $principalId,
        public string $permission,
        public ?string $resourceType = null,
        public ?string $resourceId = null,
        public ?int $expiresAt = null,
        public array $metadata = [],
    ) {
    }

    public function isExpiredAt(?int $timestamp = null): bool
    {
        return $this->expiresAt !== null && $this->expiresAt <= ($timestamp ?? time());
    }
}
