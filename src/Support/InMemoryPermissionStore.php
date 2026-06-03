<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Authorization\Permission\Permission;
use Infocyph\AuthLayer\Authorization\Permission\PermissionAssignmentStoreInterface;
use Infocyph\AuthLayer\Authorization\Permission\PermissionStoreInterface;

final class InMemoryPermissionStore implements PermissionStoreInterface, PermissionAssignmentStoreInterface
{
    /**
     * @var array<string, Permission>
     */
    private array $permissions = [];

    /**
     * @var array<string, list<string>>
     */
    private array $accountPermissions = [];

    /**
     * @var array<string, list<string>>
     */
    private array $rolePermissions = [];

    public function save(Permission $permission): void
    {
        $this->permissions[$permission->id] = $permission;
    }

    public function assignPermissionToAccount(string $accountId, string $permissionId): void
    {
        $this->assign($this->accountPermissions, $accountId, $permissionId);
    }

    public function revokePermissionFromAccount(string $accountId, string $permissionId): void
    {
        $this->revoke($this->accountPermissions, $accountId, $permissionId);
    }

    public function assignPermissionToRole(string $roleId, string $permissionId): void
    {
        $this->assign($this->rolePermissions, $roleId, $permissionId);
    }

    public function revokePermissionFromRole(string $roleId, string $permissionId): void
    {
        $this->revoke($this->rolePermissions, $roleId, $permissionId);
    }

    public function permissionsForAccount(string $accountId): array
    {
        return $this->resolve($this->accountPermissions[$accountId] ?? []);
    }

    public function permissionsForRoles(array $roleIds): array
    {
        $ids = [];

        foreach ($roleIds as $roleId) {
            foreach ($this->rolePermissions[$roleId] ?? [] as $permissionId) {
                $ids[$permissionId] = true;
            }
        }

        return $this->resolve(array_keys($ids));
    }

    /**
     * @param array<string, list<string>> $bucket
     */
    private function assign(array &$bucket, string $key, string $permissionId): void
    {
        $bucket[$key] ??= [];

        if (! in_array($permissionId, $bucket[$key], true)) {
            $bucket[$key][] = $permissionId;
        }
    }

    /**
     * @param array<string, list<string>> $bucket
     */
    private function revoke(array &$bucket, string $key, string $permissionId): void
    {
        $bucket[$key] = array_values(array_filter(
            $bucket[$key] ?? [],
            static fn (string $assignedPermissionId): bool => $assignedPermissionId !== $permissionId,
        ));
    }

    /**
     * @param list<string> $ids
     * @return list<Permission>
     */
    private function resolve(array $ids): array
    {
        $permissions = [];

        foreach ($ids as $id) {
            if (isset($this->permissions[$id])) {
                $permissions[$id] = $this->permissions[$id];
            }
        }

        return array_values($permissions);
    }
}
