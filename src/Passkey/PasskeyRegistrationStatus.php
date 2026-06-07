<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Passkey;

enum PasskeyRegistrationStatus: string
{
    case INVALID = 'invalid';

    case REGISTERED = 'registered';

    case STARTED = 'started';
}
