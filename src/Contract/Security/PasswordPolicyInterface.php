<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Security;

interface PasswordPolicyInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function validate(string $plainPassword, array $context = []): PasswordPolicyResult;
}
