<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Storage;

use Infocyph\AuthLayer\Account\AccountInterface;

interface AccountProviderInterface
{
    public function findById(string $id): ?AccountInterface;

    public function findByIdentifier(string $identifier): ?AccountInterface;
}
