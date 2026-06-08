<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Benchmarks\Authorization;

use Infocyph\AuthLayer\Authorization\Gate\Gate;
use Infocyph\AuthLayer\Authorization\Gate\PermissionAuthorizer;
use Infocyph\AuthLayer\Authorization\Grant\AccessGrant;
use Infocyph\AuthLayer\Authorization\Grant\GrantResolver;
use Infocyph\AuthLayer\Authorization\Permission\Permission;
use Infocyph\AuthLayer\Authorization\Permission\PermissionResolver;
use Infocyph\AuthLayer\Authorization\Role\Role;
use Infocyph\AuthLayer\Authorization\Role\RolePermissionResolver;
use Infocyph\AuthLayer\Principal\Principal;
use Infocyph\AuthLayer\Principal\PrincipalType;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\InMemoryGrantStore;
use Infocyph\AuthLayer\Support\InMemoryPermissionStore;
use Infocyph\AuthLayer\Support\InMemoryRoleStore;
use PhpBench\Attributes as Bench;

final class AuthorizationCoreBench
{
    private Gate $gate;

    private PermissionAuthorizer $permissionAuthorizer;

    private Principal $principal;

    #[Bench\BeforeMethods('setUpGate')]
    public function benchGateCan(): void
    {
        $this->gate->can($this->principal, 'documents:view');
    }

    #[Bench\BeforeMethods('setUpPermissionAuthorizer')]
    public function benchPermissionAuthorizerCan(): void
    {
        $this->permissionAuthorizer->can(
            $this->principal,
            'documents:view',
            ['type' => 'document', 'id' => 'doc-1'],
        );
    }

    public function setUpGate(): void
    {
        $this->principal = new Principal('principal-1', PrincipalType::ACCOUNT, 'acct-1');
        $this->gate = new Gate();
        $this->gate->define('documents:view', static fn(): bool => true);
    }

    public function setUpPermissionAuthorizer(): void
    {
        $roles = new InMemoryRoleStore();
        $permissions = new InMemoryPermissionStore();
        $grants = new InMemoryGrantStore(new FrozenClock(1000));

        $role = new Role('role-1', 'editor');
        $permission = new Permission('perm-1', 'documents:*');

        $roles->save($role);
        $roles->assignRole('acct-1', $role->id);
        $permissions->save($permission);
        $permissions->assignPermissionToRole($role->id, $permission->id);
        $grants->save(new AccessGrant('grant-1', 'principal-1', 'documents:view', 'document', 'doc-1', 1300));

        $this->principal = new Principal('principal-1', PrincipalType::ACCOUNT, 'acct-1');
        $this->permissionAuthorizer = new PermissionAuthorizer(
            new PermissionResolver($permissions),
            new RolePermissionResolver($roles, $permissions),
            new GrantResolver($grants, clock: new FrozenClock(1000)),
        );
    }
}
