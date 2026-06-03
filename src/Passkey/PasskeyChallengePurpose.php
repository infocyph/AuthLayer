<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Passkey;

enum PasskeyChallengePurpose: string
{
    case REGISTRATION = 'registration';
    case AUTHENTICATION = 'authentication';
    case STEP_UP = 'step_up';
}
