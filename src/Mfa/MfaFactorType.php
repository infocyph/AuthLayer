<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Mfa;

enum MfaFactorType: string
{
    case TOTP = 'totp';
    case HOTP = 'hotp';
    case SMS = 'sms';
    case EMAIL = 'email';
    case PASSKEY = 'passkey';
    case RECOVERY_CODE = 'recovery_code';
    case CUSTOM = 'custom';
}
