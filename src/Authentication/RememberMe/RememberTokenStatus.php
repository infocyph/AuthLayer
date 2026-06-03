<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\RememberMe;

enum RememberTokenStatus: string
{
    case ISSUED = 'issued';
    case VERIFIED = 'verified';
    case ROTATED = 'rotated';
    case REVOKED = 'revoked';
    case REUSED = 'reused';
    case EXPIRED = 'expired';
    case INVALID = 'invalid';
}
