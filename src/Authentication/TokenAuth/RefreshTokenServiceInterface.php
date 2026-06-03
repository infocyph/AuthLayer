<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\TokenAuth;

use Infocyph\AuthLayer\Contract\Security\TokenVerificationResult;

interface RefreshTokenServiceInterface
{
    public function issue(RefreshTokenClaims $claims): IssuedRefreshToken;

    public function verify(string $token): TokenVerificationResult;
}
