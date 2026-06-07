<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Session;

enum SessionStatus: string
{
    case ACTIVE = 'active';

    case EXPIRED = 'expired';
}
