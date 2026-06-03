<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\EmailVerification;

enum EmailVerificationStatus: string
{
    case ISSUED = 'issued';
    case VERIFIED = 'verified';
    case INVALID = 'invalid';
    case EXPIRED = 'expired';
    case CONSUMED = 'consumed';
}
