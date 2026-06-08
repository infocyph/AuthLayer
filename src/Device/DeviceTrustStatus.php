<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Device;

enum DeviceTrustStatus: string
{
    case REVOKED = 'revoked';

    case TRUSTED = 'trusted';

    case UNTRUSTED = 'untrusted';
}
