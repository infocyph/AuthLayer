<?php

declare(strict_types=1);

use Infocyph\AuthLayer\Account\AccountManager;
use Infocyph\AuthLayer\Account\AccountStatus;
use Infocyph\AuthLayer\Exception\AuthenticationException;
use Infocyph\AuthLayer\Principal\CurrentPrincipalContext;
use Infocyph\AuthLayer\Principal\Principal;
use Infocyph\AuthLayer\Principal\PrincipalType;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\InMemoryAccountStore;
use Infocyph\AuthLayer\Tests\Fixtures\TestAuthIdGenerator;

it('creates accounts and rejects duplicate identifiers', function (): void {
    $store = new InMemoryAccountStore();
    $manager = new AccountManager($store, $store, new TestAuthIdGenerator(), new FrozenClock(1000));

    $created = $manager->create('alice@example.com', 'hash', ['role' => 'user']);
    $duplicate = $manager->create('alice@example.com', 'hash');

    expect($created->successful())->toBeTrue()
        ->and($created->account?->id())->toBe('acct-1')
        ->and($duplicate->failed())->toBeTrue()
        ->and($duplicate->code)->toBe('account_already_exists');
});

it('updates account status, metadata, and verification state', function (): void {
    $store = new InMemoryAccountStore();
    $manager = new AccountManager($store, $store, new TestAuthIdGenerator(), new FrozenClock(1000));
    $created = $manager->create('alice@example.com', 'hash', status: AccountStatus::PENDING_VERIFICATION);
    $accountId = $created->account?->id();

    expect($accountId)->not->toBeNull();

    $verified = $manager->markVerified($accountId);
    $metadataUpdated = $manager->updateMetadata($accountId, ['risk' => 'low']);
    $locked = $manager->lock($accountId);
    $requiredPasswordChange = $manager->requirePasswordChange($accountId);
    $requiredMfa = $manager->requireMfaEnrollment($accountId);
    $suspended = $manager->suspend($accountId);
    $unlocked = $manager->unlock($accountId);
    $disabled = $manager->disable($accountId);

    expect($verified->successful())->toBeTrue()
        ->and($verified->account?->metadata()['verified_at'])->toBe(1000)
        ->and($metadataUpdated->account?->metadata())->toBe(['risk' => 'low'])
        ->and($locked->account?->status())->toBe(AccountStatus::LOCKED)
        ->and($requiredPasswordChange->account?->status())->toBe(AccountStatus::PASSWORD_CHANGE_REQUIRED)
        ->and($requiredMfa->account?->status())->toBe(AccountStatus::MFA_ENROLLMENT_REQUIRED)
        ->and($suspended->account?->status())->toBe(AccountStatus::SUSPENDED)
        ->and($unlocked->account?->status())->toBe(AccountStatus::ACTIVE)
        ->and($disabled->account?->status())->toBe(AccountStatus::DISABLED);
});

it('manages the current principal context', function (): void {
    $context = new CurrentPrincipalContext();
    $principal = new Principal('principal-1', PrincipalType::ACCOUNT, 'acct-1', ['role' => 'admin']);

    $context->set($principal);

    expect($context->get())->toBe($principal)
        ->and($context->require())->toBe($principal);

    $context->clear();

    expect($context->get())->toBeNull();

    $context->require();
})->throws(AuthenticationException::class);
