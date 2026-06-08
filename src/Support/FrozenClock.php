<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Contract\Clock\ClockInterface;

final class FrozenClock implements ClockInterface
{
    public function __construct(
        private int $now,
    ) {}

    public function freezeAt(int $now): self
    {
        $this->now = $now;

        return $this;
    }

    public function now(): int
    {
        return $this->now;
    }

    public function tick(int $seconds = 1): self
    {
        $this->now += $seconds;

        return $this;
    }
}
