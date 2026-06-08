<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Role;

interface RoleAssignmentStoreInterface
{
    public function assignRole(string $accountId, string $roleId): void;

    public function revokeRole(string $accountId, string $roleId): void;

    public function save(Role $role): void;
}
