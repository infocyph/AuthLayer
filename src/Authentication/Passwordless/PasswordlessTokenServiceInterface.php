<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Passwordless;

use Infocyph\AuthLayer\Contract\Security\TokenVerificationResult;

interface PasswordlessTokenServiceInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function issue(string $identifier, array $context = []): string;

    public function verify(string $token): TokenVerificationResult;
}
