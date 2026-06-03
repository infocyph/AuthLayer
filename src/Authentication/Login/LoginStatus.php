<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Login;

enum LoginStatus: string
{
    case AUTHENTICATED = 'authenticated';
    case INVALID_CREDENTIALS = 'invalid_credentials';
    case ACCOUNT_DISABLED = 'account_disabled';
    case ACCOUNT_LOCKED = 'account_locked';
    case EMAIL_VERIFICATION_REQUIRED = 'email_verification_required';
    case PASSWORD_CHANGE_REQUIRED = 'password_change_required';
    case MFA_REQUIRED = 'mfa_required';
    case PASSKEY_REQUIRED = 'passkey_required';
    case STEP_UP_REQUIRED = 'step_up_required';
}
