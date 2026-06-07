<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Mfa;

enum MfaFactorType: string
{
    case CUSTOM = 'custom';

    case EMAIL = 'email';

    case HOTP = 'hotp';

    case PASSKEY = 'passkey';

    case RECOVERY_CODE = 'recovery_code';

    case SMS = 'sms';

    case TOTP = 'totp';
}
