<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Grant;

enum DelegationStatus: string
{
    case GRANTED = 'granted';
    case REVOKED = 'revoked';
    case LISTED = 'listed';
}
