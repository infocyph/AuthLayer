<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Principal;

enum PrincipalType: string
{
    case ACCOUNT = 'account';

    case GUEST = 'guest';

    case IMPERSONATED = 'impersonated';

    case SERVICE = 'service';
}
