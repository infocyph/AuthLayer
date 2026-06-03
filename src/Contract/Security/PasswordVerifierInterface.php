<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Security;

interface PasswordVerifierInterface
{
    public function verify(string $plainPassword, string $storedHash): PasswordVerificationResult;
}
