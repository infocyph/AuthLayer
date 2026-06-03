<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Role;

interface RoleStoreInterface
{
    /**
     * @return list<Role>
     */
    public function rolesForAccount(string $accountId): array;
}
