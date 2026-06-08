<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Scope;

enum ScopeType: string
{
    case ORGANIZATION = 'organization';

    case TENANT = 'tenant';

    case WORKSPACE = 'workspace';
}
