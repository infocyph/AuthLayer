<?php

declare(strict_types=1);

use Infocyph\AuthLayer\Account\Account;
use Infocyph\AuthLayer\Account\AccountStatus;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Contract\Storage\LockoutReason;
use Infocyph\AuthLayer\Notification\AuthNotification;
use Infocyph\AuthLayer\Notification\AuthNotificationType;
use Infocyph\AuthLayer\Support\AcceptAllPasswordPolicy;
use Infocyph\AuthLayer\Support\ArrayTtlStore;
use Infocyph\AuthLayer\Support\CollectingAuthNotifier;
use Infocyph\AuthLayer\Support\CollectingEventDispatcher;
use Infocyph\AuthLayer\Support\ContextValue;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\InMemoryAccountStore;
use Infocyph\AuthLayer\Support\InMemoryAuditEventStore;
use Infocyph\AuthLayer\Support\InMemoryCounterStore;
use Infocyph\AuthLayer\Support\InMemoryLockoutStore;
use Infocyph\AuthLayer\Support\NullAuthNotifier;
use Infocyph\AuthLayer\Support\NullEventDispatcher;
use Infocyph\AuthLayer\Support\NullTtlStore;
use Infocyph\AuthLayer\Support\RandomAuthIdGenerator;
it('provides deterministic TTL behavior with a frozen clock', function (): void {
    $clock = new FrozenClock(1000);
    $store = new ArrayTtlStore($clock);

    $store->put('key', 'value', 10);

    expect($store->get('key'))->toBe('value');

    $clock->tick(11);

    expect($store->get('key', 'fallback'))->toBe('fallback')
        ->and($store->pull('key', 'fallback'))->toBe('fallback');
});

it('provides counter TTL behavior for lockout windows', function (): void {
    $clock = new FrozenClock(1000);
    $counters = new InMemoryCounterStore($clock);

    expect($counters->increment('failures', ttlSeconds: 10))->toBe(1)
        ->and($counters->increment('failures', ttlSeconds: 10))->toBe(2);

    $clock->tick(11);

    expect($counters->increment('failures', ttlSeconds: 10))->toBe(1);
});

it('expires lockouts when their deadline passes', function (): void {
    $clock = new FrozenClock(1000);
    $locks = new InMemoryLockoutStore($clock);

    $locks->lock('acct-1', LockoutReason::TOO_MANY_LOGIN_ATTEMPTS, 1010);

    expect($locks->isLocked('acct-1'))->toBeTrue();

    $clock->tick(11);

    expect($locks->isLocked('acct-1'))->toBeFalse();
});

it('collects notifications and events and can flush them', function (): void {
    $notifier = new CollectingAuthNotifier();
    $dispatcher = new CollectingEventDispatcher();
    $audit = new InMemoryAuditEventStore();

    $notification = new AuthNotification(AuthNotificationType::LOGIN_ALERT, 'acct-1', ['ip' => '127.0.0.1']);
    $event = new stdClass();

    $notifier->send($notification);
    $dispatcher->dispatch($event);
    $audit->record(new Infocyph\AuthLayer\Audit\AuthEvent('evt-1', AuthEventType::LOGIN_SUCCESS, Infocyph\AuthLayer\Audit\AuthEventSeverity::INFO, 'acct-1', null, null, null, 'corr-1', 1000));

    expect($notifier->notifications())->toHaveCount(1)
        ->and($dispatcher->events())->toHaveCount(1)
        ->and($audit->events())->toHaveCount(1);

    $notifier->flush();
    $dispatcher->flush();
    $audit->flush();

    expect($notifier->notifications())->toBe([])
        ->and($dispatcher->events())->toBe([])
        ->and($audit->events())->toBe([]);
});

it('provides null implementations without side effects', function (): void {
    $ttl = new NullTtlStore();
    $notifier = new NullAuthNotifier();
    $dispatcher = new NullEventDispatcher();

    $ttl->put('key', 'value', 10);
    $notifier->send(new AuthNotification(AuthNotificationType::LOGIN_ALERT, null));
    $dispatcher->dispatch(new stdClass());

    expect($ttl->get('key', 'fallback'))->toBe('fallback')
        ->and($ttl->pull('key', 'fallback'))->toBe('fallback');
});

it('provides context value coercion helpers', function (): void {
    $context = ['session_id' => 'sess-1', 'attempts' => 3, 'empty' => ''];

    expect(ContextValue::stringOrNull($context, 'session_id'))->toBe('sess-1')
        ->and(ContextValue::stringOrNull($context, 'empty'))->toBeNull()
        ->and(ContextValue::int($context, 'attempts', 0))->toBe(3)
        ->and(ContextValue::int($context, 'missing', 7))->toBe(7);
});

it('provides permissive password policy and random identifiers', function (): void {
    $policy = new AcceptAllPasswordPolicy();
    $ids = new RandomAuthIdGenerator();

    expect($policy->validate('secret')->valid)->toBeTrue()
        ->and($ids->accountId())->toStartWith('acct_')
        ->and($ids->sessionId())->toStartWith('sess_')
        ->and($ids->permissionId())->toStartWith('perm_');
});

it('mutates accounts in the in-memory account store', function (): void {
    $store = new InMemoryAccountStore();
    $account = new Account('acct-1', 'alice@example.com', AccountStatus::PENDING_VERIFICATION, 'hash', ['role' => 'user']);

    $store->save($account);
    $store->markVerified('acct-1', 1234);
    $store->updatePasswordHash('acct-1', 'hash-2');
    $store->updateMetadata('acct-1', ['role' => 'admin']);
    $store->updateStatus('acct-1', AccountStatus::SUSPENDED);

    $stored = $store->findById('acct-1');

    expect($stored)->not->toBeNull()
        ->and($stored?->passwordHash())->toBe('hash-2')
        ->and($stored?->metadata())->toBe(['role' => 'admin'])
        ->and($stored?->status())->toBe(AccountStatus::SUSPENDED);
});
