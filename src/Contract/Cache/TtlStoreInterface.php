<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Cache;

interface TtlStoreInterface
{
    public function put(string $key, mixed $value, int $ttlSeconds): void;

    public function get(string $key, mixed $default = null): mixed;

    public function pull(string $key, mixed $default = null): mixed;

    public function delete(string $key): void;
}
