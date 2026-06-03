<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Storage;

interface LockoutStoreInterface
{
    public function lock(string $accountId, LockoutReason $reason, ?int $until = null): void;

    public function unlock(string $accountId): void;

    public function isLocked(string $accountId): bool;
}
