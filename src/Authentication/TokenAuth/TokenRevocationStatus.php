<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\TokenAuth;

enum TokenRevocationStatus: string
{
    case ALREADY_REVOKED = 'already_revoked';

    case REVOKED = 'revoked';
}
