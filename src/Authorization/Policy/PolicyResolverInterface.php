<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Policy;

interface PolicyResolverInterface
{
    public function resolve(mixed $resource): ?PolicyInterface;
}
