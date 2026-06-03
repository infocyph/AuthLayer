<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\PasswordReset;

use Infocyph\AuthLayer\Contract\Security\TokenVerificationResult;

interface PasswordResetTokenServiceInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function issue(string $accountId, array $context = []): string;

    public function verify(string $token): TokenVerificationResult;
}
