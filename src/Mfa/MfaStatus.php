<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Mfa;

enum MfaStatus: string
{
    case ENROLLED = 'enrolled';
    case ACTIVATED = 'activated';
    case CHALLENGE_ISSUED = 'challenge_issued';
    case VERIFIED = 'verified';
    case RECOVERY_CODE_VERIFIED = 'recovery_code_verified';
    case REMOVED = 'removed';
    case INVALID = 'invalid';
    case EXPIRED = 'expired';
}
