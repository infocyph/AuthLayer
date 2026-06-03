<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Security;

use Infocyph\AuthLayer\Authentication\TokenAuth\AccessTokenClaims;

interface AccessTokenServiceInterface
{
    public function issue(AccessTokenClaims $claims): string;

    public function verify(string $token): TokenVerificationResult;
}
