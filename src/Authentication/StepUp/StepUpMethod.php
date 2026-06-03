<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\StepUp;

enum StepUpMethod: string
{
    case RECENT_AUTH = 'recent_auth';
    case MFA = 'mfa';
    case PASSKEY = 'passkey';
    case PASSWORD = 'password';
}
