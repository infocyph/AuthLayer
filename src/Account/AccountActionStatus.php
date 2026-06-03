<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Account;

enum AccountActionStatus: string
{
    case CREATED = 'created';
    case UPDATED = 'updated';
    case ALREADY_EXISTS = 'already_exists';
    case NOT_FOUND = 'not_found';
}
