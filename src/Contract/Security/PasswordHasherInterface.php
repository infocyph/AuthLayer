<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Security;

interface PasswordHasherInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function hash(string $plainPassword, array $context = []): string;
}
