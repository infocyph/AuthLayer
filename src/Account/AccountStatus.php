<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Account;

enum AccountStatus: string
{
    case ACTIVE = 'active';
    case DISABLED = 'disabled';
    case SUSPENDED = 'suspended';
    case LOCKED = 'locked';
    case PENDING_VERIFICATION = 'pending_verification';
    case PASSWORD_CHANGE_REQUIRED = 'password_change_required';
    case MFA_ENROLLMENT_REQUIRED = 'mfa_enrollment_required';
}
