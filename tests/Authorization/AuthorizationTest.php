<?php

declare(strict_types=1);

use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Authorization\Decision\AuthorizationDecision;
use Infocyph\AuthLayer\Authorization\Gate\AuditingAuthorizer;
use Infocyph\AuthLayer\Authorization\Gate\Gate;
use Infocyph\AuthLayer\Authorization\Gate\PermissionAuthorizer;
use Infocyph\AuthLayer\Authorization\Grant\AccessGrant;
use Infocyph\AuthLayer\Authorization\Grant\DelegationManager;
use Infocyph\AuthLayer\Authorization\Grant\GrantResolver;
use Infocyph\AuthLayer\Authorization\Permission\PermissionManager;
use Infocyph\AuthLayer\Authorization\Permission\PermissionResolver;
use Infocyph\AuthLayer\Authorization\Role\RoleManager;
use Infocyph\AuthLayer\Authorization\Role\RolePermissionResolver;
use Infocyph\AuthLayer\Exception\AuthorizationException;
use Infocyph\AuthLayer\Principal\Principal;
use Infocyph\AuthLayer\Principal\PrincipalType;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\InMemoryAuditEventStore;
use Infocyph\AuthLayer\Support\InMemoryGrantStore;
use Infocyph\AuthLayer\Support\InMemoryPermissionStore;
use Infocyph\AuthLayer\Support\InMemoryRoleStore;
use Infocyph\AuthLayer\Tests\Fixtures\TestAuthIdGenerator;
use Infocyph\AuthLayer\Tests\Fixtures\TestPolicy;
use Infocyph\AuthLayer\Tests\Fixtures\TestPolicyResolver;

it('resolves gate abilities, before hooks, after hooks, and policies', function (): void {
    $policy = new TestPolicy(
        decisions: ['posts:edit' => AuthorizationDecision::allow('policy_allowed')],
        defaultDecision: AuthorizationDecision::deny('policy_denied'),
    );
    $resolver = new TestPolicyResolver($policy);
    $gate = new Gate($resolver);

    $gate->before(static function ($_principal, string $ability): ?bool {
        unset($_principal);

        return $ability === 'system:shutdown' ? true : null;
    });
    $gate->define('posts:view', static fn () => true);
    $gate->after(static function ($_principal, string $ability, mixed $_resource, AuthorizationDecision $decision): AuthorizationDecision {
        unset($_principal, $_resource);

        return $ability === 'posts:view' ? AuthorizationDecision::allow('after_override') : $decision;
    });

    $principal = new Principal('acct-1', PrincipalType::ACCOUNT, 'acct-1');

    expect($gate->can($principal, 'system:shutdown')->allowed)->toBeTrue()
        ->and($gate->can($principal, 'posts:view')->code)->toBe('after_override')
        ->and($gate->can($principal, 'posts:edit', new stdClass)->code)->toBe('policy_allowed')
        ->and($gate->can($principal, 'missing')->allowed)->toBeFalse();
});

it('throws authorization exceptions for denied gate decisions', function (): void {
    $gate = new Gate;
    $principal = new Principal('acct-1', PrincipalType::ACCOUNT, 'acct-1');

    $gate->authorize($principal, 'missing');
})->throws(AuthorizationException::class);

it('authorizes via direct permissions, role permissions, and grants', function (): void {
    $ids = new TestAuthIdGenerator;
    $roles = new InMemoryRoleStore;
    $permissions = new InMemoryPermissionStore;
    $grants = new InMemoryGrantStore(new FrozenClock(1000));

    $roleManager = new RoleManager($roles, $roles, $ids);
    $permissionManager = new PermissionManager($permissions, $permissions, $ids);
    $role = $roleManager->create('editor');
    $permission = $permissionManager->create('posts:*');
    $directPermission = $permissionManager->create('reports:view');

    $roleManager->assign('acct-1', $role->id);
    $permissionManager->assignToRole($role->id, $permission->id);
    $permissionManager->assignToAccount('acct-1', $directPermission->id);
    $grants->save(new AccessGrant('grant-1', 'principal-1', 'documents:view', 'document', 'doc-1'));

    $authorizer = new PermissionAuthorizer(
        new PermissionResolver($permissions),
        new RolePermissionResolver($roles, $permissions),
        new GrantResolver($grants, clock: new FrozenClock(1000)),
    );

    $principal = new Principal('principal-1', PrincipalType::ACCOUNT, 'acct-1');
    $guest = new Principal('guest-1', PrincipalType::GUEST, null);

    expect($authorizer->can($principal, 'posts:edit')->allowed)->toBeTrue()
        ->and($authorizer->can($principal, 'reports:view')->allowed)->toBeTrue()
        ->and($authorizer->can($principal, 'documents:view', ['type' => 'document', 'id' => 'doc-1'])->allowed)->toBeTrue()
        ->and($authorizer->can($guest, 'posts:view')->allowed)->toBeFalse();
});

it('audits denied authorizations through the wrapper authorizer', function (): void {
    $audit = new InMemoryAuditEventStore;
    $authorizer = new AuditingAuthorizer(new Gate, $audit, new TestAuthIdGenerator, new FrozenClock(1000));
    $principal = new Principal('principal-1', PrincipalType::ACCOUNT, 'acct-1');

    $decision = $authorizer->can($principal, 'missing', null, ['session_id' => 'sess-1']);

    expect($decision->allowed)->toBeFalse()
        ->and(array_map(static fn ($event) => $event->type, $audit->events()))->toBe([AuthEventType::AUTHORIZATION_DENIED]);
});

it('manages delegated access and exposes principal grants', function (): void {
    $audit = new InMemoryAuditEventStore;
    $store = new InMemoryGrantStore(new FrozenClock(1000));
    $manager = new DelegationManager($store, $audit, new TestAuthIdGenerator, new FrozenClock(1000));

    $granted = $manager->grant('principal-1', 'documents:view', 'document', 'doc-1', 1300, ['session_id' => 'sess-1']);
    $listed = $manager->listForPrincipal('principal-1');
    $revoked = $manager->revoke($granted->grant?->id ?? '', 'principal-1');

    expect($granted->successful())->toBeTrue()
        ->and($listed->grants)->toHaveCount(1)
        ->and($revoked->successful())->toBeTrue()
        ->and(array_map(static fn ($event) => $event->type, $audit->events()))->toBe([AuthEventType::DELEGATED_ACCESS_GRANTED, AuthEventType::DELEGATED_ACCESS_REVOKED]);
});

it('persists and revokes role and permission assignments', function (): void {
    $ids = new TestAuthIdGenerator;
    $roles = new InMemoryRoleStore;
    $permissions = new InMemoryPermissionStore;
    $roleManager = new RoleManager($roles, $roles, $ids);
    $permissionManager = new PermissionManager($permissions, $permissions, $ids);

    $role = $roleManager->create('auditor', ['scope' => 'billing']);
    $permission = $permissionManager->create('billing:view', ['scope' => 'billing']);

    $roleManager->assign('acct-1', $role->id);
    $permissionManager->assignToAccount('acct-1', $permission->id);
    $permissionManager->assignToRole($role->id, $permission->id);

    expect($roleManager->forAccount('acct-1'))->toHaveCount(1)
        ->and($permissionManager->forAccount('acct-1'))->toHaveCount(1)
        ->and($permissionManager->forRoles([$role->id]))->toHaveCount(1);

    $roleManager->revoke('acct-1', $role->id);
    $permissionManager->revokeFromAccount('acct-1', $permission->id);
    $permissionManager->revokeFromRole($role->id, $permission->id);

    expect($roleManager->forAccount('acct-1'))->toBe([])
        ->and($permissionManager->forAccount('acct-1'))->toBe([])
        ->and($permissionManager->forRoles([$role->id]))->toBe([]);
});

it('ignores expired and revoked grants during authorization', function (): void {
    $clock = new FrozenClock(1000);
    $store = new InMemoryGrantStore($clock);
    $resolver = new GrantResolver($store, clock: $clock);
    $principal = new Principal('principal-1', PrincipalType::ACCOUNT, 'acct-1');

    $store->save(new AccessGrant('grant-1', 'principal-1', 'documents:*', 'document', 'doc-1', 900));

    expect($resolver->forPrincipal($principal->id(), Infocyph\AuthLayer\Authorization\Gate\Ability::from('documents:view', ['type' => 'document', 'id' => 'doc-1'])))->toBe([]);

    $store->save(new AccessGrant('grant-2', 'principal-1', 'documents:*', 'document', 'doc-1', 1200));

    expect($resolver->forPrincipal($principal->id(), Infocyph\AuthLayer\Authorization\Gate\Ability::from('documents:view', ['type' => 'document', 'id' => 'doc-1'])))->toHaveCount(1);

    $store->revoke('grant-2');

    expect($resolver->forPrincipal($principal->id(), Infocyph\AuthLayer\Authorization\Gate\Ability::from('documents:view', ['type' => 'document', 'id' => 'doc-1'])))->toBe([]);
});
