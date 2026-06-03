<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Principal;

interface CurrentPrincipalProviderInterface
{
    public function get(): ?PrincipalInterface;

    public function require(): PrincipalInterface;
}
