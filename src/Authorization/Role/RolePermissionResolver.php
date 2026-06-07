<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Role;

use Infocyph\AuthLayer\Authorization\Permission\Permission;
use Infocyph\AuthLayer\Authorization\Permission\PermissionStoreInterface;

final readonly class RolePermissionResolver
{
    public function __construct(
        private RoleStoreInterface $roles,
        private PermissionStoreInterface $permissions,
    ) {}

    /**
     * @return list<Permission>
     */
    public function forAccount(string $accountId): array
    {
        $roles = $this->roles->rolesForAccount($accountId);
        $roleIds = array_map(static fn(Role $role): string => $role->id, $roles);

        if ($roleIds === []) {
            return [];
        }

        return $this->permissions->permissionsForRoles($roleIds);
    }
}
