<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Grant;

enum DelegationStatus: string
{
    case GRANTED = 'granted';

    case LISTED = 'listed';

    case REVOKED = 'revoked';
}
