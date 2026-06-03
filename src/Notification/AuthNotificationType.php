<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Notification;

enum AuthNotificationType: string
{
    case PASSWORD_RESET_REQUESTED = 'password_reset_requested';
    case EMAIL_VERIFICATION_REQUESTED = 'email_verification_requested';
    case MFA_CHALLENGE_REQUESTED = 'mfa_challenge_requested';
    case LOGIN_ALERT = 'login_alert';
    case NEW_DEVICE_ALERT = 'new_device_alert';
    case ACCOUNT_LOCKED = 'account_locked';
    case PASSWORD_CHANGED = 'password_changed';
    case PASSKEY_REGISTERED = 'passkey_registered';
    case PASSKEY_REMOVED = 'passkey_removed';
    case SUSPICIOUS_ACTIVITY = 'suspicious_activity';
    case PASSWORDLESS_LOGIN_REQUESTED = 'passwordless_login_requested';
    case DELEGATED_ACCESS_GRANTED = 'delegated_access_granted';
    case DELEGATED_ACCESS_REVOKED = 'delegated_access_revoked';
}
