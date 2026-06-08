<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\RememberMe;

final readonly class RememberToken
{
    public function __construct(
        public string $value,
        public string $selector,
        public string $familyId,
        public string $verifierHash,
        public int $expiresAt,
    ) {}
}
