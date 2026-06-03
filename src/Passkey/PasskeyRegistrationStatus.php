<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Passkey;

enum PasskeyRegistrationStatus: string
{
    case STARTED = 'started';
    case REGISTERED = 'registered';
    case INVALID = 'invalid';
}
