<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Authentication\TokenAuth\RefreshTokenRecord;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Storage\RefreshTokenStoreInterface;

final class InMemoryRefreshTokenStore implements RefreshTokenStoreInterface
{
    /**
     * @var array<string, RefreshTokenRecord>
     */
    private array $records = [];

    /**
     * @var array<string, true>
     */
    private array $revokedFamilies = [];

    public function __construct(
        private readonly ClockInterface $clock = new SystemClock(),
    ) {
    }

    public function save(RefreshTokenRecord $record): void
    {
        $this->records[$record->id] = $record;
    }

    public function find(string $tokenId): ?RefreshTokenRecord
    {
        return $this->records[$tokenId] ?? null;
    }

    public function rotate(string $tokenId, RefreshTokenRecord $replacement): void
    {
        $current = $this->records[$tokenId] ?? null;

        if ($current !== null) {
            $this->records[$tokenId] = new RefreshTokenRecord(
                id: $current->id,
                accountId: $current->accountId,
                tokenHash: $current->tokenHash,
                familyId: $current->familyId,
                clientId: $current->clientId,
                deviceId: $current->deviceId,
                issuedAt: $current->issuedAt,
                expiresAt: $current->expiresAt,
                rotatedAt: $this->clock->now(),
                revokedAt: $current->revokedAt,
                metadata: $current->metadata,
            );
        }

        $this->records[$replacement->id] = $replacement;
    }

    public function revokeFamily(string $familyId): void
    {
        $this->revokedFamilies[$familyId] = true;

        foreach ($this->records as $tokenId => $record) {
            if ($record->familyId !== $familyId) {
                continue;
            }

            $this->records[$tokenId] = new RefreshTokenRecord(
                id: $record->id,
                accountId: $record->accountId,
                tokenHash: $record->tokenHash,
                familyId: $record->familyId,
                clientId: $record->clientId,
                deviceId: $record->deviceId,
                issuedAt: $record->issuedAt,
                expiresAt: $record->expiresAt,
                rotatedAt: $record->rotatedAt,
                revokedAt: $this->clock->now(),
                metadata: $record->metadata,
            );
        }
    }

    public function wasFamilyRevoked(string $familyId): bool
    {
        return isset($this->revokedFamilies[$familyId]);
    }
}
