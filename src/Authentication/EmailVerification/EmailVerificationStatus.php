<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\EmailVerification;

enum EmailVerificationStatus: string
{
    case CONSUMED = 'consumed';

    case EXPIRED = 'expired';

    case INVALID = 'invalid';

    case ISSUED = 'issued';

    case VERIFIED = 'verified';
}
