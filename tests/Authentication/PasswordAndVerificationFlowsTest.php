<?php

declare(strict_types=1);

use Infocyph\AuthLayer\Account\Account;
use Infocyph\AuthLayer\Account\AccountStatus;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Authentication\EmailVerification\EmailVerificationManager;
use Infocyph\AuthLayer\Authentication\EmailVerification\EmailVerificationStatus;
use Infocyph\AuthLayer\Authentication\PasswordChange\PasswordChangeManager;
use Infocyph\AuthLayer\Authentication\PasswordChange\PasswordChangeStatus;
use Infocyph\AuthLayer\Authentication\PasswordReset\PasswordResetManager;
use Infocyph\AuthLayer\Authentication\PasswordReset\PasswordResetStatus;
use Infocyph\AuthLayer\Support\CollectingAuthNotifier;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\InMemoryAccountStore;
use Infocyph\AuthLayer\Support\InMemoryAuditEventStore;
use Infocyph\AuthLayer\Support\InMemoryEmailVerificationStore;
use Infocyph\AuthLayer\Support\InMemoryPasswordResetStore;
use Infocyph\AuthLayer\Tests\Fixtures\TestAuthIdGenerator;
use Infocyph\AuthLayer\Tests\Fixtures\TestEmailVerificationTokenService;
use Infocyph\AuthLayer\Tests\Fixtures\TestPasswordHasher;
use Infocyph\AuthLayer\Tests\Fixtures\TestPasswordPolicy;
use Infocyph\AuthLayer\Tests\Fixtures\TestPasswordResetTokenService;
use Infocyph\AuthLayer\Tests\Fixtures\TestPasswordVerifier;

it('changes passwords and enforces policy for plain-password updates', function (): void {
    $accounts = new InMemoryAccountStore();
    $accounts->save(new Account('acct-1', 'alice@example.com', AccountStatus::ACTIVE, 'current-hash'));
    $audit = new InMemoryAuditEventStore();
    $notifier = new CollectingAuthNotifier();
    $manager = new PasswordChangeManager($accounts, $accounts, new TestPasswordVerifier(), $audit, $notifier, new TestAuthIdGenerator(), new FrozenClock(1000));

    $changed = $manager->change('acct-1', 'current-hash', 'new-hash', ['session_id' => 'sess-1']);
    $invalid = $manager->change('acct-1', 'wrong', 'new-hash');
    $policyFailed = $manager->changeWithPlainPassword('acct-1', 'current-hash', 'weak', new TestPasswordHasher(), new TestPasswordPolicy(valid: false, violations: ['too_short'], code: 'weak_password'));

    expect($changed->status)->toBe(PasswordChangeStatus::CHANGED)
        ->and($accounts->findById('acct-1')?->passwordHash())->toBe('new-hash')
        ->and($invalid->status)->toBe(PasswordChangeStatus::INVALID_CREDENTIALS)
        ->and($policyFailed->status)->toBe(PasswordChangeStatus::POLICY_FAILED)
        ->and($notifier->notifications())->toHaveCount(1)
        ->and(array_map(static fn($event) => $event->type, $audit->events()))->toBe([AuthEventType::PASSWORD_CHANGED]);
});

it('returns account-not-found when password changes cannot be applied', function (): void {
    $accounts = new InMemoryAccountStore();
    $accounts->save(new Account('acct-1', 'alice@example.com', AccountStatus::ACTIVE, null));

    $result = (new PasswordChangeManager(
        $accounts,
        $accounts,
        new TestPasswordVerifier(),
        new InMemoryAuditEventStore(),
        new CollectingAuthNotifier(),
        new TestAuthIdGenerator(),
        new FrozenClock(1000),
    ))->change('acct-1', 'ignored', 'new-hash');

    expect($result->status)->toBe(PasswordChangeStatus::ACCOUNT_NOT_FOUND)
        ->and($result->failed())->toBeTrue();
});

it('issues and completes password resets, including consumed and policy-failure paths', function (): void {
    $clock = new FrozenClock(1000);
    $accounts = new InMemoryAccountStore();
    $accounts->save(new Account('acct-1', 'alice@example.com', AccountStatus::ACTIVE, 'old-hash'));
    $tokens = new TestPasswordResetTokenService();
    $store = new InMemoryPasswordResetStore($clock);
    $audit = new InMemoryAuditEventStore();
    $notifier = new CollectingAuthNotifier();
    $manager = new PasswordResetManager($tokens, $store, $accounts, $notifier, $audit, new TestAuthIdGenerator(), 300, $clock);

    $issued = $manager->issue('acct-1', ['ip' => '127.0.0.1']);
    $completed = $manager->complete($issued->token ?? '', 'new-hash');
    $consumed = $manager->complete($issued->token ?? '', 'other-hash');
    $policyFailed = $manager->completeWithPlainPassword('missing-token', 'weak', new TestPasswordHasher(), new TestPasswordPolicy(valid: false, violations: ['too_short'], code: 'weak_password'));

    expect($issued->status)->toBe(PasswordResetStatus::REQUESTED)
        ->and($completed->status)->toBe(PasswordResetStatus::COMPLETED)
        ->and($accounts->findById('acct-1')?->passwordHash())->toBe('new-hash')
        ->and($consumed->status)->toBe(PasswordResetStatus::CONSUMED)
        ->and($policyFailed->status)->toBe(PasswordResetStatus::POLICY_FAILED)
        ->and($notifier->notifications())->toHaveCount(1)
        ->and(array_map(static fn($event) => $event->type, $audit->events()))->toBe([AuthEventType::PASSWORD_RESET_REQUESTED, AuthEventType::PASSWORD_RESET_COMPLETED]);
});

it('hashes plain passwords during reset and rejects orphaned reset tokens', function (): void {
    $clock = new FrozenClock(1000);
    $accounts = new InMemoryAccountStore();
    $accounts->save(new Account('acct-1', 'alice@example.com', AccountStatus::ACTIVE, 'old-hash'));
    $tokens = new TestPasswordResetTokenService();
    $store = new InMemoryPasswordResetStore($clock);
    $manager = new PasswordResetManager(
        $tokens,
        $store,
        $accounts,
        new CollectingAuthNotifier(),
        new InMemoryAuditEventStore(),
        new TestAuthIdGenerator(),
        300,
        $clock,
    );

    $issued = $manager->issue('acct-1');
    $completed = $manager->completeWithPlainPassword($issued->token ?? '', 'new-secret', new TestPasswordHasher('hashed::'));
    $tokens->verifications['orphan-token'] = new Infocyph\AuthLayer\Contract\Security\TokenVerificationResult(true, subjectId: 'acct-1', claims: ['request_id' => 'missing']);
    $orphan = $manager->complete('orphan-token', 'ignored');

    expect($completed->status)->toBe(PasswordResetStatus::COMPLETED)
        ->and($accounts->findById('acct-1')?->passwordHash())->toBe('hashed::new-secret')
        ->and($orphan->status)->toBe(PasswordResetStatus::INVALID)
        ->and($orphan->code)->toBe('reset_request_not_found');
});

it('verifies email addresses and handles invalid and expired verification requests', function (): void {
    $clock = new FrozenClock(1000);
    $accounts = new InMemoryAccountStore();
    $accounts->save(new Account('acct-1', 'alice@example.com', AccountStatus::PENDING_VERIFICATION));
    $tokens = new TestEmailVerificationTokenService();
    $store = new InMemoryEmailVerificationStore($clock);
    $audit = new InMemoryAuditEventStore();
    $notifier = new CollectingAuthNotifier();
    $manager = new EmailVerificationManager($tokens, $store, $accounts, $notifier, $audit, new TestAuthIdGenerator(), 60, $clock);

    $issued = $manager->issue('acct-1', 'alice@example.com', ['device_id' => 'dev-1']);
    $verified = $manager->verify($issued->token ?? '');
    $consumed = $manager->verify($issued->token ?? '');

    $expiredIssue = $manager->issue('acct-1', 'alice@example.com');
    $clock->tick(61);
    $expired = $manager->verify($expiredIssue->token ?? '');
    $invalid = $manager->verify('missing-token');

    expect($issued->status)->toBe(EmailVerificationStatus::ISSUED)
        ->and($verified->status)->toBe(EmailVerificationStatus::VERIFIED)
        ->and($accounts->findById('acct-1')?->status())->toBe(AccountStatus::ACTIVE)
        ->and($consumed->status)->toBe(EmailVerificationStatus::CONSUMED)
        ->and($expired->status)->toBe(EmailVerificationStatus::EXPIRED)
        ->and($invalid->status)->toBe(EmailVerificationStatus::INVALID)
        ->and($notifier->notifications())->toHaveCount(2)
        ->and(array_map(static fn($event) => $event->type, $audit->events()))->toContain(AuthEventType::EMAIL_VERIFICATION_REQUESTED, AuthEventType::EMAIL_VERIFIED);
});

it('includes request metadata in verification notifications and rejects orphaned verification tokens', function (): void {
    $clock = new FrozenClock(1000);
    $accounts = new InMemoryAccountStore();
    $accounts->save(new Account('acct-1', 'alice@example.com', AccountStatus::PENDING_VERIFICATION));
    $tokens = new TestEmailVerificationTokenService();
    $notifier = new CollectingAuthNotifier();
    $manager = new EmailVerificationManager(
        $tokens,
        new InMemoryEmailVerificationStore($clock),
        $accounts,
        $notifier,
        new InMemoryAuditEventStore(),
        new TestAuthIdGenerator(),
        60,
        $clock,
    );

    $issued = $manager->issue('acct-1', 'alice@example.com', ['session_id' => 'sess-1']);
    $notification = $notifier->notifications()[0];
    $tokens->verifications['orphan-token'] = new Infocyph\AuthLayer\Contract\Security\TokenVerificationResult(true, subjectId: 'acct-1', claims: ['request_id' => 'missing']);
    $orphan = $manager->verify('orphan-token');

    expect($notification->payload)->toMatchArray([
        'email' => 'alice@example.com',
        'session_id' => 'sess-1',
        'token' => $issued->token,
    ])
        ->and($notification->payload['request_id'] ?? null)->not->toBeNull()
        ->and($orphan->status)->toBe(EmailVerificationStatus::INVALID)
        ->and($orphan->code)->toBe('verification_request_not_found');
});
