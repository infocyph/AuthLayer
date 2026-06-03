<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Login;

use Infocyph\AuthLayer\Principal\PrincipalInterface;

interface AuthenticatorInterface
{
    public function login(LoginRequest $request): LoginResult;

    public function logout(PrincipalInterface $principal, ?string $sessionId = null): void;
}
