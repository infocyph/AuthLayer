<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Clock;

interface ClockInterface
{
    public function now(): int;
}
