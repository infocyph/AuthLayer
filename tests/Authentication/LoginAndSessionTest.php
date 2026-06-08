<?php

declare(strict_types=1);

use Infocyph\AuthLayer\Account\Account;
use Infocyph\AuthLayer\Account\AccountStatus;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Authentication\Lockout\LockoutConfig;
use Infocyph\AuthLayer\Authentication\Lockout\LockoutManager;
use Infocyph\AuthLayer\Authentication\Login\Authenticator;
use Infocyph\AuthLayer\Authentication\Login\LoginRequest;
use Infocyph\AuthLayer\Authentication\Login\LoginStatus;
use Infocyph\AuthLayer\Authentication\Session\SessionConfig;
use Infocyph\AuthLayer\Authentication\Session\SessionManager;
use Infocyph\AuthLayer\Authentication\Session\SessionStatus;
use Infocyph\AuthLayer\Contract\Security\PasswordVerificationResult;
use Infocyph\AuthLayer\Exception\SessionException;
use Infocyph\AuthLayer\Principal\Principal;
use Infocyph\AuthLayer\Principal\PrincipalType;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\InMemoryAccountStore;
use Infocyph\AuthLayer\Support\InMemoryAuditEventStore;
use Infocyph\AuthLayer\Support\InMemoryCounterStore;
use Infocyph\AuthLayer\Support\InMemoryLockoutStore;
use Infocyph\AuthLayer\Support\InMemorySessionStore;
use Infocyph\AuthLayer\Tests\Fixtures\TestAuthIdGenerator;
use Infocyph\AuthLayer\Tests\Fixtures\TestPasswordVerifier;

it('creates, rotates, touches, and revokes sessions', function (): void {
    $clock = new FrozenClock(1000);
    $sessions = new InMemorySessionStore;
    $manager = new SessionManager($sessions, new TestAuthIdGenerator, new SessionConfig(300, 60), $clock);

    $created = $manager->create('acct-1', 'dev-1', ['ip' => '127.0.0.1']);
    $touched = $manager->touch($created->id);
    $rotated = $manager->rotate($created->id);

    expect($created->id)->toBe('sess-1')
        ->and($touched?->lastSeenAt)->toBe(1000)
        ->and($rotated->id)->toBe('sess-2')
        ->and($sessions->find('sess-1'))->toBeNull()
        ->and($sessions->find('sess-2'))->not->toBeNull();

    $clock->tick(301);

    expect($manager->status($rotated))->toBe(SessionStatus::EXPIRED)
        ->and($manager->isRecentlyAuthenticated($rotated, 60))->toBeFalse();

    $manager->revoke('sess-2');

    expect($sessions->find('sess-2'))->toBeNull();
});

it('reports active session state and supports account-wide logout', function (): void {
    $clock = new FrozenClock(1000);
    $ids = new TestAuthIdGenerator;
    $store = new InMemorySessionStore;
    $sessions = new SessionManager($store, $ids, new SessionConfig(300, 60), $clock);
    $created = $sessions->create('acct-1', 'dev-1', ['recent' => true]);
    $recent = new Infocyph\AuthLayer\Authentication\Session\AuthSession('sess-recent', 'acct-1', 'dev-1', 1000, 1000, 1300, 980);

    expect($sessions->status($created))->toBe(SessionStatus::ACTIVE)
        ->and($sessions->isRecentlyAuthenticated($recent, 60))->toBeTrue();

    $accounts = new InMemoryAccountStore;
    $accounts->save(new Account('acct-1', 'alice@example.com', AccountStatus::ACTIVE, 'hash'));
    $audit = new InMemoryAuditEventStore;
    $lockouts = new LockoutManager(new InMemoryCounterStore($clock), new InMemoryLockoutStore($clock), $audit, $ids, new LockoutConfig, $clock);
    $authenticator = new Authenticator($accounts, $accounts, new TestPasswordVerifier, $sessions, $ids, $audit, $lockouts, $clock);

    $authenticator->logout(new Principal('acct-1', PrincipalType::ACCOUNT, 'acct-1'));

    expect($store->find($created->id))->toBeNull()
        ->and(array_map(static fn ($event) => $event->type, $audit->events()))->toBe([AuthEventType::LOGOUT]);
});

it('revokes all account sessions except the current one', function (): void {
    $store = new InMemorySessionStore;
    $manager = new SessionManager($store, new TestAuthIdGenerator, new SessionConfig(300, 60), new FrozenClock(1000));

    $first = $manager->create('acct-1');
    $second = $manager->create('acct-1');
    $third = $manager->create('acct-2');

    $manager->revokeAllForAccount('acct-1', $second->id);

    expect($store->find($first->id))->toBeNull()
        ->and($store->find($second->id))->not->toBeNull()
        ->and($store->find($third->id))->not->toBeNull();
});

it('throws when rotating an unknown session', function (): void {
    $manager = new SessionManager(new InMemorySessionStore, new TestAuthIdGenerator, new SessionConfig, new FrozenClock(1000));

    $manager->rotate('missing');
})->throws(SessionException::class);

it('authenticates valid credentials, rehashes passwords, and records login/logout audit events', function (): void {
    $clock = new FrozenClock(1000);
    $accounts = new InMemoryAccountStore;
    $accounts->save(new Account('acct-1', 'alice@example.com', AccountStatus::ACTIVE, 'legacy-hash', ['team' => 'ops']));

    $ids = new TestAuthIdGenerator;
    $audit = new InMemoryAuditEventStore;
    $sessionManager = new SessionManager(new InMemorySessionStore, $ids, new SessionConfig(3600, 900), $clock);
    $lockouts = new LockoutManager(new InMemoryCounterStore($clock), new InMemoryLockoutStore($clock), $audit, $ids, new LockoutConfig(3, 3, 3, 60, 120), $clock);
    $verifier = new TestPasswordVerifier;
    $verifier->result = new PasswordVerificationResult(true, true, 'rehash-hash');
    $authenticator = new Authenticator($accounts, $accounts, $verifier, $sessionManager, $ids, $audit, $lockouts, $clock);

    $result = $authenticator->login(new LoginRequest('alice@example.com', 'secret', context: ['device_id' => 'dev-1', 'ip' => '127.0.0.1']));

    expect($result->successful())->toBeTrue()
        ->and($result->status)->toBe(LoginStatus::AUTHENTICATED)
        ->and($result->session?->deviceId)->toBe('dev-1')
        ->and($accounts->findById('acct-1')?->passwordHash())->toBe('rehash-hash')
        ->and(array_map(static fn ($event) => $event->type, $audit->events()))->toBe([AuthEventType::LOGIN_SUCCESS]);

    $authenticator->logout($result->principal ?? new Principal('acct-1', PrincipalType::ACCOUNT, 'acct-1'), $result->session?->id);

    expect(array_map(static fn ($event) => $event->type, $audit->events()))->toBe([AuthEventType::LOGIN_SUCCESS, AuthEventType::LOGOUT]);
});

it('rejects invalid credentials and account status constraints', function (): void {
    $clock = new FrozenClock(1000);
    $accounts = new InMemoryAccountStore;
    $accounts->save(new Account('acct-1', 'alice@example.com', AccountStatus::PENDING_VERIFICATION, 'hash'));
    $accounts->save(new Account('acct-2', 'bob@example.com', AccountStatus::ACTIVE, 'hash'));

    $ids = new TestAuthIdGenerator;
    $audit = new InMemoryAuditEventStore;
    $lockouts = new LockoutManager(new InMemoryCounterStore($clock), new InMemoryLockoutStore($clock), $audit, $ids, new LockoutConfig(2, 2, 2, 60, 120), $clock);
    $authenticator = new Authenticator(
        $accounts,
        $accounts,
        new TestPasswordVerifier,
        new SessionManager(new InMemorySessionStore, $ids, new SessionConfig, $clock),
        $ids,
        $audit,
        $lockouts,
        $clock,
    );

    $missing = $authenticator->login(new LoginRequest('missing@example.com', 'secret'));
    $pending = $authenticator->login(new LoginRequest('alice@example.com', 'hash'));
    $invalid = $authenticator->login(new LoginRequest('bob@example.com', 'wrong'));
    $locked = $authenticator->login(new LoginRequest('bob@example.com', 'wrong'));

    expect($missing->status)->toBe(LoginStatus::INVALID_CREDENTIALS)
        ->and($pending->status)->toBe(LoginStatus::EMAIL_VERIFICATION_REQUIRED)
        ->and($invalid->status)->toBe(LoginStatus::INVALID_CREDENTIALS)
        ->and($locked->status)->toBe(LoginStatus::ACCOUNT_LOCKED)
        ->and(array_map(static fn ($event) => $event->type, $audit->events()))->toContain(AuthEventType::LOGIN_FAILURE, AuthEventType::LOCKOUT_TRIGGERED);
});

it('maps all guarded account states and missing password hashes during login', function (): void {
    $clock = new FrozenClock(1000);
    $accounts = new InMemoryAccountStore;
    $accounts->save(new Account('acct-disabled', 'disabled@example.com', AccountStatus::DISABLED, 'hash'));
    $accounts->save(new Account('acct-suspended', 'suspended@example.com', AccountStatus::SUSPENDED, 'hash'));
    $accounts->save(new Account('acct-change', 'change@example.com', AccountStatus::PASSWORD_CHANGE_REQUIRED, 'hash'));
    $accounts->save(new Account('acct-mfa', 'mfa@example.com', AccountStatus::MFA_ENROLLMENT_REQUIRED, 'hash'));
    $accounts->save(new Account('acct-empty', 'empty@example.com', AccountStatus::ACTIVE, null));

    $ids = new TestAuthIdGenerator;
    $audit = new InMemoryAuditEventStore;
    $authenticator = new Authenticator(
        $accounts,
        $accounts,
        new TestPasswordVerifier,
        new SessionManager(new InMemorySessionStore, $ids, new SessionConfig, $clock),
        $ids,
        $audit,
        new LockoutManager(new InMemoryCounterStore($clock), new InMemoryLockoutStore($clock), $audit, $ids, new LockoutConfig, $clock),
        $clock,
    );

    $disabled = $authenticator->login(new LoginRequest('disabled@example.com', 'hash'));
    $suspended = $authenticator->login(new LoginRequest('suspended@example.com', 'hash'));
    $change = $authenticator->login(new LoginRequest('change@example.com', 'hash'));
    $mfa = $authenticator->login(new LoginRequest('mfa@example.com', 'hash'));
    $empty = $authenticator->login(new LoginRequest('empty@example.com', 'hash'));

    expect($disabled->status)->toBe(LoginStatus::ACCOUNT_DISABLED)
        ->and($suspended->status)->toBe(LoginStatus::ACCOUNT_DISABLED)
        ->and($change->status)->toBe(LoginStatus::PASSWORD_CHANGE_REQUIRED)
        ->and($mfa->status)->toBe(LoginStatus::MFA_REQUIRED)
        ->and($empty->status)->toBe(LoginStatus::INVALID_CREDENTIALS)
        ->and($empty->code)->toBe('password_not_configured');
});
