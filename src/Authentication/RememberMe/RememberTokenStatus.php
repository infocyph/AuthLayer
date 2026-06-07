<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\RememberMe;

enum RememberTokenStatus: string
{
    case EXPIRED = 'expired';

    case INVALID = 'invalid';

    case ISSUED = 'issued';

    case REUSED = 'reused';

    case REVOKED = 'revoked';

    case ROTATED = 'rotated';

    case VERIFIED = 'verified';
}
