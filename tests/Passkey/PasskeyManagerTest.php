<?php

declare(strict_types=1);

use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Passkey\PasskeyAuthenticationResult;
use Infocyph\AuthLayer\Passkey\PasskeyAuthenticationStatus;
use Infocyph\AuthLayer\Passkey\PasskeyManager;
use Infocyph\AuthLayer\Passkey\PasskeyRegistrationResult;
use Infocyph\AuthLayer\Passkey\PasskeyRegistrationStatus;
use Infocyph\AuthLayer\Support\CollectingAuthNotifier;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\InMemoryAuditEventStore;
use Infocyph\AuthLayer\Support\InMemoryPasskeyCredentialStore;
use Infocyph\AuthLayer\Tests\Fixtures\TestAuthIdGenerator;
use Infocyph\AuthLayer\Tests\Fixtures\TestPasskeyService;

it('starts and completes passkey registration and authentication', function (): void {
    $clock = new FrozenClock(1000);
    $service = new TestPasskeyService();
    $credentials = new InMemoryPasskeyCredentialStore($clock);
    $audit = new InMemoryAuditEventStore();
    $notifier = new CollectingAuthNotifier();
    $manager = new PasskeyManager($service, $credentials, $audit, $notifier, new TestAuthIdGenerator(), $clock);

    $startedRegistration = $manager->startRegistration('acct-1');
    $finishedRegistration = $manager->finishRegistration(new PasskeyRegistrationResult('pk-reg-1', 'acct-1', 'credential-1', 'public-key', ['usb'], 1), ['device_id' => 'dev-1']);
    $startedAuthentication = $manager->startAuthentication('acct-1');
    $finishedAuthentication = $manager->finishAuthentication(new PasskeyAuthenticationResult('pk-auth-1', 'credential-1', 'client', 'auth', 'sig'), ['session_id' => 'sess-1']);

    expect($startedRegistration->status)->toBe(PasskeyRegistrationStatus::STARTED)
        ->and($finishedRegistration->status)->toBe(PasskeyRegistrationStatus::REGISTERED)
        ->and($credentials->findForAccount('acct-1'))->toHaveCount(1)
        ->and($startedAuthentication->status)->toBe(PasskeyAuthenticationStatus::STARTED)
        ->and($finishedAuthentication->status)->toBe(PasskeyAuthenticationStatus::VERIFIED)
        ->and($credentials->findByCredentialId('credential-1')?->lastUsedAt)->toBe(1000)
        ->and($notifier->notifications())->toHaveCount(1)
        ->and(array_map(static fn($event) => $event->type, $audit->events()))->toContain(AuthEventType::PASSKEY_REGISTERED, AuthEventType::PASSKEY_USED);
});

it('revokes passkey credentials and reports invalid authentications', function (): void {
    $clock = new FrozenClock(1000);
    $service = new TestPasskeyService();
    $service->verification = new Infocyph\AuthLayer\Passkey\PasskeyVerificationResult(false, reason: 'bad_signature');
    $credentials = new InMemoryPasskeyCredentialStore($clock);
    $audit = new InMemoryAuditEventStore();
    $notifier = new CollectingAuthNotifier();
    $manager = new PasskeyManager($service, $credentials, $audit, $notifier, new TestAuthIdGenerator(), $clock);

    $credential = $manager->finishRegistration(new PasskeyRegistrationResult('pk-reg-1', 'acct-1', 'credential-1', 'public-key'));
    $invalid = $manager->finishAuthentication(new PasskeyAuthenticationResult('pk-auth-1', 'credential-1', 'client', 'auth', 'sig'));
    $manager->revokeCredential('acct-1', $credential->credential?->credentialId ?? '');

    expect($invalid->status)->toBe(PasskeyAuthenticationStatus::INVALID)
        ->and($credentials->findByCredentialId('credential-1'))->toBeNull()
        ->and($notifier->notifications())->toHaveCount(2)
        ->and(array_map(static fn($event) => $event->type, $audit->events()))->toContain(AuthEventType::PASSKEY_REMOVED);
});

it('starts anonymous authentication and skips usage updates when verification lacks counters', function (): void {
    $clock = new FrozenClock(1000);
    $service = new TestPasskeyService();
    $service->verification = new Infocyph\AuthLayer\Passkey\PasskeyVerificationResult(true, accountId: 'acct-1');
    $credentials = new InMemoryPasskeyCredentialStore($clock);
    $credentials->save(new Infocyph\AuthLayer\Passkey\PasskeyCredential('cred-record-1', 'acct-1', 'credential-1', 'public-key', 1, ['usb'], 1000));
    $manager = new PasskeyManager(
        $service,
        $credentials,
        new InMemoryAuditEventStore(),
        new CollectingAuthNotifier(),
        new TestAuthIdGenerator(),
        $clock,
    );

    $started = $manager->startAuthentication();
    $verified = $manager->finishAuthentication(new PasskeyAuthenticationResult('pk-auth-1', 'credential-1', 'client', 'auth', 'sig'));

    expect($started->status)->toBe(PasskeyAuthenticationStatus::STARTED)
        ->and($started->challenge?->accountId)->toBeNull()
        ->and($verified->status)->toBe(PasskeyAuthenticationStatus::VERIFIED)
        ->and($credentials->findByCredentialId('credential-1')?->lastUsedAt)->toBeNull();
});
