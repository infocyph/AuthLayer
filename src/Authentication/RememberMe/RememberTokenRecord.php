<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\RememberMe;

final readonly class RememberTokenRecord
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public string $id,
        public string $accountId,
        public string $deviceId,
        public string $selector,
        public string $verifierHash,
        public string $familyId,
        public int $issuedAt,
        public int $expiresAt,
        public ?int $lastUsedAt = null,
        public ?int $rotatedAt = null,
        public ?int $revokedAt = null,
        public array $metadata = [],
    ) {
    }

    public function isExpiredAt(?int $timestamp = null): bool
    {
        return $this->expiresAt <= ($timestamp ?? time());
    }
}
