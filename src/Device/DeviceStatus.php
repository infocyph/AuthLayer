<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Device;

enum DeviceStatus: string
{
    case REGISTERED = 'registered';
    case TRUSTED = 'trusted';
    case TOUCHED = 'touched';
    case REVOKED = 'revoked';
    case NOT_FOUND = 'not_found';
}
