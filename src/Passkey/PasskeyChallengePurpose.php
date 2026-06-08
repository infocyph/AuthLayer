<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Passkey;

enum PasskeyChallengePurpose: string
{
    case AUTHENTICATION = 'authentication';

    case REGISTRATION = 'registration';

    case STEP_UP = 'step_up';
}
