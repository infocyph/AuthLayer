<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Role;

final readonly class Role
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public string $id,
        public string $name,
        public array $metadata = [],
    ) {
    }
}
