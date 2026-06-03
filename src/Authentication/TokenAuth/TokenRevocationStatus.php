<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\TokenAuth;

enum TokenRevocationStatus: string
{
    case REVOKED = 'revoked';
    case NOT_FOUND = 'not_found';
}
