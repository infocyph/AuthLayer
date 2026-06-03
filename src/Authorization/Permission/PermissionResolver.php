<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Permission;

final readonly class PermissionResolver
{
    public function __construct(
        private PermissionStoreInterface $permissions,
    ) {
    }

    /**
     * @return list<Permission>
     */
    public function forAccount(string $accountId): array
    {
        return $this->permissions->permissionsForAccount($accountId);
    }
}
