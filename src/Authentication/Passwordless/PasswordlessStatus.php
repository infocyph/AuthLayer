<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Passwordless;

enum PasswordlessStatus: string
{
    case ISSUED = 'issued';
    case VERIFIED = 'verified';
    case INVALID = 'invalid';
    case EXPIRED = 'expired';
}
