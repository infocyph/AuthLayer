<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\TokenAuth;

final readonly class RefreshTokenRecord
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public string $id,
        public string $accountId,
        public string $tokenHash,
        public string $familyId,
        public ?string $clientId,
        public ?string $deviceId,
        public int $issuedAt,
        public int $expiresAt,
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
