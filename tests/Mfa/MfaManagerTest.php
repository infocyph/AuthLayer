<?php

declare(strict_types=1);

use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Contract\Cache\TtlStoreInterface;
use Infocyph\AuthLayer\Mfa\MfaChallengePurpose;
use Infocyph\AuthLayer\Mfa\MfaFactorType;
use Infocyph\AuthLayer\Mfa\MfaManager;
use Infocyph\AuthLayer\Mfa\MfaStatus;
use Infocyph\AuthLayer\Mfa\MfaVerificationResult;
use Infocyph\AuthLayer\Mfa\RecoveryCodeVerificationResult;
use Infocyph\AuthLayer\Support\ArrayTtlStore;
use Infocyph\AuthLayer\Support\CollectingAuthNotifier;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\InMemoryAuditEventStore;
use Infocyph\AuthLayer\Support\InMemoryMfaFactorStore;
use Infocyph\AuthLayer\Tests\Fixtures\TestAuthIdGenerator;
use Infocyph\AuthLayer\Tests\Fixtures\TestMfaVerifier;
use Infocyph\AuthLayer\Tests\Fixtures\TestRecoveryCodeService;

it('enrolls, activates, challenges, verifies, and removes MFA factors', function (): void {
    $clock = new FrozenClock(1000);
    $store = new InMemoryMfaFactorStore;
    $ttl = new ArrayTtlStore($clock);
    $audit = new InMemoryAuditEventStore;
    $notifier = new CollectingAuthNotifier;
    $manager = new MfaManager($store, new TestMfaVerifier, new TestRecoveryCodeService, $ttl, $audit, $notifier, new TestAuthIdGenerator, 60, 120, $clock);

    $enrolled = $manager->enrollFactor('acct-1', MfaFactorType::TOTP, 'Phone', ['device_id' => 'dev-1']);
    $factorId = $enrolled->factor?->id ?? '';
    $activated = $manager->activateFactor('acct-1', $factorId);
    $challenge = $manager->issueChallenge('acct-1', MfaChallengePurpose::LOGIN, $factorId, ['session_id' => 'sess-1']);
    $verified = $manager->verifyChallenge($challenge->challenge?->id ?? '', '123456', ['session_id' => 'sess-1']);
    $removed = $manager->removeFactor('acct-1', $factorId);

    expect($enrolled->status)->toBe(MfaStatus::ENROLLED)
        ->and($enrolled->recoveryCodes)->toHaveCount(10)
        ->and($activated->status)->toBe(MfaStatus::ACTIVATED)
        ->and($challenge->status)->toBe(MfaStatus::CHALLENGE_ISSUED)
        ->and($verified->status)->toBe(MfaStatus::VERIFIED)
        ->and($manager->isSatisfied('acct-1', 'sess-1'))->toBeTrue()
        ->and($removed->status)->toBe(MfaStatus::REMOVED)
        ->and($notifier->notifications())->toHaveCount(1)
        ->and(array_map(static fn ($event) => $event->type, $audit->events()))->toContain(AuthEventType::MFA_ENROLLED, AuthEventType::MFA_CHALLENGED, AuthEventType::MFA_DISABLED);
});

it('handles invalid, expired, and recovery-code MFA flows', function (): void {
    $clock = new FrozenClock(1000);
    $store = new InMemoryMfaFactorStore;
    $verifier = new TestMfaVerifier;
    $verifier->result = new MfaVerificationResult(false, reason: 'bad_code');
    $recoveryCodes = new TestRecoveryCodeService;
    $recoveryCodes->verificationMap['recovery-1'] = new RecoveryCodeVerificationResult(true);
    $recoveryCodes->verificationMap['other'] = new RecoveryCodeVerificationResult(false, 'bad_recovery');
    $ttl = new class implements TtlStoreInterface
    {
        /** @var array<string, mixed> */
        private array $items = [];

        public function delete(string $key): void
        {
            unset($this->items[$key]);
        }

        public function get(string $key, mixed $default = null): mixed
        {
            return $this->items[$key] ?? $default;
        }

        public function pull(string $key, mixed $default = null): mixed
        {
            $value = $this->get($key, $default);
            unset($this->items[$key]);

            return $value;
        }

        public function put(string $key, mixed $value, int $_ttlSeconds): void
        {
            unset($_ttlSeconds);
            $this->items[$key] = $value;
        }
    };
    $audit = new InMemoryAuditEventStore;
    $manager = new MfaManager(
        $store,
        $verifier,
        $recoveryCodes,
        $ttl,
        $audit,
        new CollectingAuthNotifier,
        new TestAuthIdGenerator,
        10,
        120,
        $clock,
    );

    $enrolled = $manager->enrollFactor('acct-1', MfaFactorType::EMAIL, 'Email', enabled: true, recoveryCodeCount: 1);
    $challenge = $manager->issueChallenge('acct-1');
    $invalid = $manager->verifyChallenge($challenge->challenge?->id ?? '', 'wrong');
    $recovery = $manager->verifyRecoveryCode('acct-1', 'recovery-1', ['session_id' => 'sess-1']);
    $expiredChallenge = $manager->issueChallenge('acct-1');
    $clock->tick(11);
    $expired = $manager->verifyChallenge($expiredChallenge->challenge?->id ?? '', '123456');

    expect($enrolled->successful())->toBeTrue()
        ->and($invalid->status)->toBe(MfaStatus::INVALID)
        ->and($recovery->status)->toBe(MfaStatus::RECOVERY_CODE_VERIFIED)
        ->and($expired->status)->toBe(MfaStatus::EXPIRED)
        ->and(array_map(static fn ($event) => $event->type, $audit->events()))->toContain(AuthEventType::RECOVERY_CODE_USED);
});

it('handles missing MFA factors, missing challenges, and invalid recovery codes', function (): void {
    $clock = new FrozenClock(1000);
    $notifier = new CollectingAuthNotifier;
    $manager = new MfaManager(
        new InMemoryMfaFactorStore,
        new TestMfaVerifier,
        new TestRecoveryCodeService,
        new ArrayTtlStore($clock),
        new InMemoryAuditEventStore,
        $notifier,
        new TestAuthIdGenerator,
        60,
        120,
        $clock,
    );

    $activate = $manager->activateFactor('acct-1', 'missing');
    $challenge = $manager->issueChallenge('acct-1');
    $verify = $manager->verifyChallenge('missing', '123456');
    $recovery = $manager->verifyRecoveryCode('acct-1', 'invalid');
    $remove = $manager->removeFactor('acct-1', 'missing');

    expect($activate->status)->toBe(MfaStatus::INVALID)
        ->and($challenge->status)->toBe(MfaStatus::INVALID)
        ->and($verify->status)->toBe(MfaStatus::INVALID)
        ->and($recovery->status)->toBe(MfaStatus::INVALID)
        ->and($remove->status)->toBe(MfaStatus::INVALID)
        ->and($notifier->notifications())->toBe([]);
});
