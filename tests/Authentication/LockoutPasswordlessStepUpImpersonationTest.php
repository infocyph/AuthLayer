<?php

declare(strict_types=1);

use Infocyph\AuthLayer\Account\Account;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Authentication\Impersonation\ImpersonationManager;
use Infocyph\AuthLayer\Authentication\Lockout\LockoutConfig;
use Infocyph\AuthLayer\Authentication\Lockout\LockoutManager;
use Infocyph\AuthLayer\Authentication\Lockout\LockoutStatus;
use Infocyph\AuthLayer\Authentication\Passwordless\PasswordlessManager;
use Infocyph\AuthLayer\Authentication\Passwordless\PasswordlessStatus;
use Infocyph\AuthLayer\Authentication\Session\AuthSession;
use Infocyph\AuthLayer\Authentication\StepUp\StepUpManager;
use Infocyph\AuthLayer\Authentication\StepUp\StepUpMethod;
use Infocyph\AuthLayer\Contract\Storage\LockoutReason;
use Infocyph\AuthLayer\Principal\Principal;
use Infocyph\AuthLayer\Principal\PrincipalType;
use Infocyph\AuthLayer\Support\ArrayTtlStore;
use Infocyph\AuthLayer\Support\CollectingAuthNotifier;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\InMemoryAuditEventStore;
use Infocyph\AuthLayer\Support\InMemoryCounterStore;
use Infocyph\AuthLayer\Support\InMemoryLockoutStore;
use Infocyph\AuthLayer\Tests\Fixtures\TestAuthIdGenerator;
use Infocyph\AuthLayer\Tests\Fixtures\TestPasswordlessTokenService;

it('records lockout failures, locks accounts, and clears them on unlock', function (): void {
    $clock = new FrozenClock(1000);
    $audit = new InMemoryAuditEventStore();
    $manager = new LockoutManager(
        new InMemoryCounterStore($clock),
        new InMemoryLockoutStore($clock),
        $audit,
        new TestAuthIdGenerator(),
        new LockoutConfig(2, 2, 2, 60, 120),
        $clock,
    );

    $first = $manager->recordLoginFailure('acct-1', ['session_id' => 'sess-1']);
    $second = $manager->recordLoginFailure('acct-1', ['session_id' => 'sess-1']);
    $unlock = $manager->unlock('acct-1');

    expect($first->status)->toBe(LockoutStatus::FAILURE_RECORDED)
        ->and($second->status)->toBe(LockoutStatus::LOCKED)
        ->and($manager->isLocked('acct-1'))->toBeFalse()
        ->and($unlock->status)->toBe(LockoutStatus::UNLOCKED)
        ->and(array_map(static fn($event) => $event->type, $audit->events()))->toBe([AuthEventType::LOCKOUT_TRIGGERED, AuthEventType::LOCKOUT_CLEARED]);
});

it('issues and verifies passwordless login tokens', function (): void {
    $tokens = new TestPasswordlessTokenService();
    $notifier = new CollectingAuthNotifier();
    $manager = new PasswordlessManager($tokens, $notifier);

    $issued = $manager->issue('alice@example.com', ['ip' => '127.0.0.1']);
    $verified = $manager->verify($issued->token ?? '');
    $tokens->verifications['expired'] = new Infocyph\AuthLayer\Contract\Security\TokenVerificationResult(false, failureReason: 'expired_token');
    $expired = $manager->verify('expired');

    expect($issued->status)->toBe(PasswordlessStatus::ISSUED)
        ->and($verified->status)->toBe(PasswordlessStatus::VERIFIED)
        ->and($expired->status)->toBe(PasswordlessStatus::EXPIRED)
        ->and($notifier->notifications())->toHaveCount(1);
});

it('surfaces invalid passwordless tokens and preserves notification payloads', function (): void {
    $tokens = new TestPasswordlessTokenService();
    $notifier = new CollectingAuthNotifier();
    $manager = new PasswordlessManager($tokens, $notifier);

    $issued = $manager->issue('alice@example.com', ['ip' => '127.0.0.1']);
    $invalid = $manager->verify('invalid');

    expect($invalid->status)->toBe(PasswordlessStatus::INVALID)
        ->and($notifier->notifications()[0]->payload)->toMatchArray([
            'identifier' => 'alice@example.com',
            'token' => $issued->token,
            'ip' => '127.0.0.1',
        ]);
});

it('tracks step-up satisfaction for sensitive abilities', function (): void {
    $clock = new FrozenClock(1000);
    $ttl = new ArrayTtlStore($clock);
    $manager = new StepUpManager($ttl, $clock);
    $session = new AuthSession('sess-1', 'acct-1', 'dev-1', 1000, 1000, 2000, 500);

    $required = $manager->evaluate($session, 'billing:update', ['max_age_seconds' => 100, 'method' => StepUpMethod::MFA]);
    $manager->markSatisfied('acct-1', 'sess-1', 'billing:update', StepUpMethod::MFA, 60);
    $satisfied = $manager->evaluate($session, 'billing:update', ['max_age_seconds' => 100, 'method' => StepUpMethod::MFA]);

    expect($required->required)->toBeTrue()
        ->and($manager->requiresStepUp($session, 'billing:update', ['max_age_seconds' => 100, 'method' => StepUpMethod::MFA]))->toBeFalse()
        ->and($satisfied->successful())->toBeTrue();
});

it('handles alternate step-up method input and already-recent authentication', function (): void {
    $clock = new FrozenClock(1000);
    $manager = new StepUpManager(new ArrayTtlStore($clock), $clock);
    $session = new AuthSession('sess-1', 'acct-1', 'dev-1', 1000, 1000, 2000, 980);

    $result = $manager->evaluate($session, 'profile:update', ['max_age_seconds' => 60, 'method' => 'passkey']);

    expect($result->required)->toBeFalse()
        ->and($result->code)->toBe('step_up_not_required');
});

it('records MFA and passkey lockout failures and supports manual locks', function (): void {
    $clock = new FrozenClock(1000);
    $audit = new InMemoryAuditEventStore();
    $manager = new LockoutManager(
        new InMemoryCounterStore($clock),
        new InMemoryLockoutStore($clock),
        $audit,
        new TestAuthIdGenerator(),
        new LockoutConfig(5, 1, 1, 60, 120),
        $clock,
    );

    $mfa = $manager->recordMfaFailure('acct-1', ['device_id' => 'dev-1']);
    $manager->unlock('acct-1');
    $passkey = $manager->recordPasskeyFailure('acct-1');
    $manual = $manager->lock('acct-2', LockoutReason::ADMINISTRATIVE, 1500);

    expect($mfa->status)->toBe(LockoutStatus::LOCKED)
        ->and($passkey->status)->toBe(LockoutStatus::LOCKED)
        ->and($manual->status)->toBe(LockoutStatus::LOCKED)
        ->and($manual->lockedUntil)->toBe(1500)
        ->and(array_map(static fn($event) => $event->type, $audit->events()))->toContain(AuthEventType::LOCKOUT_TRIGGERED);
});

it('starts and stops impersonation sessions with audit records', function (): void {
    $clock = new FrozenClock(1000);
    $audit = new InMemoryAuditEventStore();
    $manager = new ImpersonationManager($audit, new TestAuthIdGenerator(), $clock);
    $actor = new Principal('admin-1', PrincipalType::ACCOUNT, 'admin-1', ['role' => 'support']);
    $target = new Account('acct-1', 'alice@example.com');

    $started = $manager->startImpersonation($actor, $target, ['session_id' => 'sess-1']);
    $stopped = $manager->stopImpersonation($started->session, ['session_id' => 'sess-1']);

    expect($started->successful())->toBeTrue()
        ->and($started->principal?->type())->toBe(PrincipalType::IMPERSONATED)
        ->and($stopped->successful())->toBeTrue()
        ->and($stopped->principal?->type())->toBe(PrincipalType::ACCOUNT)
        ->and(array_map(static fn($event) => $event->type, $audit->events()))->toBe([AuthEventType::IMPERSONATION_STARTED, AuthEventType::IMPERSONATION_STOPPED]);
});
