<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\TokenAuth;

enum TokenType: string
{
    case ACCESS = 'access';

    case REFRESH = 'refresh';
}
