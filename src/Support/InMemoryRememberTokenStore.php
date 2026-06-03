<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Authentication\RememberMe\RememberTokenRecord;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Storage\RememberTokenStoreInterface;

final class InMemoryRememberTokenStore implements RememberTokenStoreInterface
{
    /**
     * @var array<string, RememberTokenRecord>
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

    public function save(RememberTokenRecord $record): void
    {
        $this->records[$record->id] = $record;
    }

    public function find(string $recordId): ?RememberTokenRecord
    {
        return $this->records[$recordId] ?? null;
    }

    public function findBySelector(string $selector): ?RememberTokenRecord
    {
        foreach ($this->records as $record) {
            if ($record->selector === $selector) {
                return $record;
            }
        }

        return null;
    }

    public function rotate(string $recordId, RememberTokenRecord $replacement): void
    {
        $current = $this->records[$recordId] ?? null;

        if ($current !== null) {
            $this->records[$recordId] = new RememberTokenRecord(
                id: $current->id,
                accountId: $current->accountId,
                deviceId: $current->deviceId,
                selector: $current->selector,
                verifierHash: $current->verifierHash,
                familyId: $current->familyId,
                issuedAt: $current->issuedAt,
                expiresAt: $current->expiresAt,
                lastUsedAt: $current->lastUsedAt,
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

        foreach ($this->records as $recordId => $record) {
            if ($record->familyId !== $familyId) {
                continue;
            }

            $this->records[$recordId] = new RememberTokenRecord(
                id: $record->id,
                accountId: $record->accountId,
                deviceId: $record->deviceId,
                selector: $record->selector,
                verifierHash: $record->verifierHash,
                familyId: $record->familyId,
                issuedAt: $record->issuedAt,
                expiresAt: $record->expiresAt,
                lastUsedAt: $record->lastUsedAt,
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
