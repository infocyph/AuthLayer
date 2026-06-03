<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Device;

enum DeviceTrustStatus: string
{
    case TRUSTED = 'trusted';
    case UNTRUSTED = 'untrusted';
    case REVOKED = 'revoked';
}
