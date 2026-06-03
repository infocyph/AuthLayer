<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Storage\LockoutReason;
use Infocyph\AuthLayer\Contract\Storage\LockoutStoreInterface;

final class InMemoryLockoutStore implements LockoutStoreInterface
{
    /**
     * @var array<string, array{reason: LockoutReason, until: int|null}>
     */
    private array $locks = [];

    public function __construct(
        private readonly ClockInterface $clock = new SystemClock(),
    ) {
    }

    public function lock(string $accountId, LockoutReason $reason, ?int $until = null): void
    {
        $this->locks[$accountId] = ['reason' => $reason, 'until' => $until];
    }

    public function unlock(string $accountId): void
    {
        unset($this->locks[$accountId]);
    }

    public function isLocked(string $accountId): bool
    {
        $lock = $this->locks[$accountId] ?? null;

        if ($lock === null) {
            return false;
        }

        if ($lock['until'] !== null && $lock['until'] <= $this->clock->now()) {
            unset($this->locks[$accountId]);

            return false;
        }

        return true;
    }
}
