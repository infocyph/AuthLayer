<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Contract\Cache\TtlStoreInterface;

final class NullTtlStore implements TtlStoreInterface
{
    public function delete(string $key): void {}

    public function get(string $key, mixed $default = null): mixed
    {
        return $default;
    }

    public function pull(string $key, mixed $default = null): mixed
    {
        return $default;
    }

    public function put(string $key, mixed $value, int $ttlSeconds): void {}
}
