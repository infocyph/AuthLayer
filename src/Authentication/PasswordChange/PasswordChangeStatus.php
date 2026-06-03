<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\PasswordChange;

enum PasswordChangeStatus: string
{
    case CHANGED = 'changed';
    case INVALID_CREDENTIALS = 'invalid_credentials';
    case ACCOUNT_NOT_FOUND = 'account_not_found';
}
