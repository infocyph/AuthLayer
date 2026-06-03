<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\PasswordReset;

enum PasswordResetStatus: string
{
    case REQUESTED = 'requested';
    case COMPLETED = 'completed';
    case INVALID = 'invalid';
    case EXPIRED = 'expired';
    case CONSUMED = 'consumed';
}
