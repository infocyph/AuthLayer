<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Contract\Cache\CounterStoreInterface;

final class InMemoryCounterStore implements CounterStoreInterface
{
    /**
     * @var array<string, int>
     */
    private array $values = [];

    public function increment(string $key, int $by = 1, ?int $ttlSeconds = null): int
    {
        $this->values[$key] = ($this->values[$key] ?? 0) + $by;

        return $this->values[$key];
    }

    public function reset(string $key): void
    {
        unset($this->values[$key]);
    }
}
