<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\PasswordReset;

enum PasswordResetStatus: string
{
    case COMPLETED = 'completed';

    case CONSUMED = 'consumed';

    case EXPIRED = 'expired';

    case INVALID = 'invalid';

    case POLICY_FAILED = 'policy_failed';

    case REQUESTED = 'requested';
}
