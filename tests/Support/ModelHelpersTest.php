<?php

declare(strict_types=1);

use Infocyph\AuthLayer\Account\Account;
use Infocyph\AuthLayer\Account\AccountStatus;
use Infocyph\AuthLayer\Authentication\EmailVerification\EmailVerificationRequest;
use Infocyph\AuthLayer\Authentication\PasswordReset\PasswordResetRequest;
use Infocyph\AuthLayer\Authentication\RememberMe\RememberTokenRecord;
use Infocyph\AuthLayer\Authentication\Session\AuthSession;
use Infocyph\AuthLayer\Authentication\TokenAuth\RefreshTokenRecord;
use Infocyph\AuthLayer\Authorization\Decision\AuthorizationDecision;
use Infocyph\AuthLayer\Authorization\Grant\AccessGrant;
use Infocyph\AuthLayer\Authorization\Scope\AuthScope;
use Infocyph\AuthLayer\Device\DeviceRecord;
use Infocyph\AuthLayer\Mfa\MfaChallenge;
use Infocyph\AuthLayer\Mfa\MfaFactor;
use Infocyph\AuthLayer\Passkey\PasskeyChallenge;
use Infocyph\AuthLayer\Passkey\PasskeyCredential;

it('supports immutable account updates', function (): void {
    $account = new Account('acct-1', 'alice@example.com', AccountStatus::ACTIVE, 'hash', ['a' => 1]);

    expect($account->withMetadata(['b' => 2])->metadata())->toBe(['b' => 2])
        ->and($account->withPasswordHash('hash-2')->passwordHash())->toBe('hash-2')
        ->and($account->withStatus(AccountStatus::LOCKED)->status())->toBe(AccountStatus::LOCKED);
});

it('supports session and device helper methods', function (): void {
    $session = new AuthSession('sess-1', 'acct-1', 'dev-1', 1000, 1000, 1100, 1000, ['ip' => '127.0.0.1']);
    $device = new DeviceRecord('dev-1', 'acct-1', 'Laptop', 'fp', false, 1000);

    expect($session->seenAt(1010)->lastSeenAt)->toBe(1010)
        ->and($session->isExpiredAt(1200))->toBeTrue()
        ->and($device->trusted()->trusted)->toBeTrue()
        ->and($device->seenAt(1020)->lastSeenAt)->toBe(1020)
        ->and($device->revokedAt(1030)->isRevoked())->toBeTrue();
});

it('supports consumable request helpers', function (): void {
    $verification = new EmailVerificationRequest('req-1', 'acct-1', 'alice@example.com', 1000, 1100);
    $reset = new PasswordResetRequest('req-2', 'acct-1', 1000, 1100);

    expect($verification->withConsumedAt(1050)->isConsumed())->toBeTrue()
        ->and($verification->isExpiredAt(1200))->toBeTrue()
        ->and($reset->withConsumedAt(1050)->consumedAt)->toBe(1050)
        ->and($reset->isExpiredAt(1200))->toBeTrue();
});

it('supports family token record helpers', function (): void {
    $remember = new RememberTokenRecord('dev-1', 'selector-1', 'hash-1', 'rec-1', 'acct-1', 'family-1', 1000, 1100);
    $refresh = new RefreshTokenRecord('hash-1', 'client-1', 'dev-1', 'token-1', 'acct-1', 'family-1', 1000, 1100);

    expect($remember->withLastUsedAt(1050)->lastUsedAt)->toBe(1050)
        ->and($remember->withRotatedAt(1060)->rotatedAt)->toBe(1060)
        ->and($remember->withRevokedAt(1070)->isRevoked())->toBeTrue()
        ->and($refresh->withRotatedAt(1060)->rotatedAt)->toBe(1060)
        ->and($refresh->withRevokedAt(1070)->isRevoked())->toBeTrue()
        ->and($refresh->isExpiredAt(1200))->toBeTrue();
});

it('supports grant, MFA, and passkey helper methods', function (): void {
    $grant = new AccessGrant('grant-1', 'principal-1', 'documents:view', 'document', 'doc-1', 1100);
    $factor = new MfaFactor('factor-1', 'acct-1', 'totp', 'Phone', false, 1000);
    $challenge = new MfaChallenge('challenge-1', 'acct-1', 'factor-1', 'login', 1000, 1100);
    $passkeyChallenge = new PasskeyChallenge('pk-1', 'acct-1', 'login', 'challenge', 1000, 1100);
    $credential = new PasskeyCredential('cred-1', 'acct-1', 'credential-1', 'public-key', 1, ['usb'], 1000);

    expect($grant->isExpiredAt(1200))->toBeTrue()
        ->and((new AccessGrant('grant-2', 'principal-1', 'documents:view', revokedAt: 1200))->isRevoked())->toBeTrue()
        ->and($factor->activated()->enabled)->toBeTrue()
        ->and($challenge->isExpiredAt(1200))->toBeTrue()
        ->and($passkeyChallenge->isExpiredAt(1200))->toBeTrue()
        ->and($credential->revokedAt(1300)->isRevoked())->toBeTrue();
});

it('supports authorization decisions and scope values', function (): void {
    $allow = AuthorizationDecision::allow('allowed_code', 'Allowed');
    $deny = AuthorizationDecision::deny('denied_code', 'Denied');
    $scope = new AuthScope('tenant-1', 'workspace-1', 'org-1', ['region' => 'us']);

    expect($allow->allowed)->toBeTrue()
        ->and($allow->code)->toBe('allowed_code')
        ->and($deny->allowed)->toBeFalse()
        ->and($scope->tenantId)->toBe('tenant-1')
        ->and($scope->metadata)->toBe(['region' => 'us']);
});
