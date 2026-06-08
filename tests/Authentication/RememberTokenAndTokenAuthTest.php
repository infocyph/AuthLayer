<?php

declare(strict_types=1);

use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Authentication\RememberMe\RememberMeManager;
use Infocyph\AuthLayer\Authentication\RememberMe\RememberTokenStatus;
use Infocyph\AuthLayer\Authentication\RememberMe\RememberTokenVerificationResult;
use Infocyph\AuthLayer\Authentication\TokenAuth\AccessTokenClaims;
use Infocyph\AuthLayer\Authentication\TokenAuth\TokenAuthManager;
use Infocyph\AuthLayer\Authentication\TokenAuth\TokenRevocationStatus;
use Infocyph\AuthLayer\Authentication\TokenAuth\TokenType;
use Infocyph\AuthLayer\Contract\Security\TokenVerificationResult;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\InMemoryAuditEventStore;
use Infocyph\AuthLayer\Support\InMemoryRefreshTokenStore;
use Infocyph\AuthLayer\Support\InMemoryRememberTokenStore;
use Infocyph\AuthLayer\Tests\Fixtures\TestAccessTokenService;
use Infocyph\AuthLayer\Tests\Fixtures\TestAuthIdGenerator;
use Infocyph\AuthLayer\Tests\Fixtures\TestRefreshTokenService;
use Infocyph\AuthLayer\Tests\Fixtures\TestRememberTokenService;

it('issues, verifies, rotates, and revokes remember-me token families', function (): void {
    $clock = new FrozenClock(1000);
    $tokens = new TestRememberTokenService();
    $store = new InMemoryRememberTokenStore($clock);
    $audit = new InMemoryAuditEventStore();
    $manager = new RememberMeManager($tokens, $store, $audit, new TestAuthIdGenerator(), $clock);

    $issued = $manager->issue('acct-1', 'dev-1', ['session_id' => 'sess-1']);
    $record = $issued->record;
    expect($record)->not->toBeNull();

    $tokens->verifications[$issued->token?->value ?? ''] = new RememberTokenVerificationResult(true, $record);
    $verified = $manager->verify($issued->token?->value ?? '');
    $rotated = $manager->rotate($record);

    $reuseRecord = $rotated->record;
    expect($reuseRecord)->not->toBeNull();
    $tokens->verifications[$rotated->token?->value ?? ''] = new RememberTokenVerificationResult(false, $reuseRecord, true, 'reuse_detected');
    $reused = $manager->verify($rotated->token?->value ?? '');

    expect($issued->status)->toBe(RememberTokenStatus::ISSUED)
        ->and($verified->status)->toBe(RememberTokenStatus::VERIFIED)
        ->and($verified->record?->lastUsedAt)->toBe(1000)
        ->and($rotated->status)->toBe(RememberTokenStatus::ROTATED)
        ->and($reused->status)->toBe(RememberTokenStatus::REUSED)
        ->and($store->wasFamilyRevoked($reuseRecord?->familyId ?? ''))->toBeTrue()
        ->and(array_map(static fn($event) => $event->type, $audit->events()))->toContain(AuthEventType::REMEMBER_TOKEN_ISSUED, AuthEventType::REMEMBER_TOKEN_REVOKED);
});

it('issues, verifies, rotates, and revokes access and refresh tokens', function (): void {
    $clock = new FrozenClock(1000);
    $ids = new TestAuthIdGenerator();
    $audit = new InMemoryAuditEventStore();
    $access = new TestAccessTokenService();
    $refreshService = new TestRefreshTokenService();
    $refreshStore = new InMemoryRefreshTokenStore($clock);
    $manager = new TokenAuthManager($access, $refreshService, $refreshStore, $audit, $ids, 300, $clock);

    $accessClaims = new AccessTokenClaims('acct-1', null, 1000, 1300, ['read'], ['device_id' => 'dev-1']);
    $issuedAccess = $manager->issueAccessToken($accessClaims, ['ip' => '127.0.0.1']);
    $verifiedAccess = $manager->verifyAccessToken($issuedAccess->token ?? '');

    $issuedRefresh = $manager->issueRefreshToken('acct-1', 'client-1', 'dev-1', ['session_id' => 'sess-1']);
    $refreshRecord = $issuedRefresh->refreshToken;
    expect($refreshRecord)->not->toBeNull();

    $verifiedRefresh = $manager->verifyRefreshToken($issuedRefresh->token ?? '');
    $rotated = $manager->rotateRefreshToken($refreshRecord, ['ip' => '127.0.0.1']);
    $revoked = $manager->revokeRefreshFamily($refreshRecord->familyId, ['account_id' => 'acct-1']);
    $alreadyRevoked = $manager->revokeRefreshFamily($refreshRecord->familyId, ['account_id' => 'acct-1']);
    $reuse = $manager->rotateRefreshToken($refreshRecord, ['ip' => '127.0.0.1']);

    expect($issuedAccess->type)->toBe(TokenType::ACCESS)
        ->and($verifiedAccess->successful())->toBeTrue()
        ->and($issuedRefresh->type)->toBe(TokenType::REFRESH)
        ->and($verifiedRefresh->verification?->verified)->toBeTrue()
        ->and($rotated->successful())->toBeTrue()
        ->and($revoked->status)->toBe(TokenRevocationStatus::REVOKED)
        ->and($alreadyRevoked->status)->toBe(TokenRevocationStatus::ALREADY_REVOKED)
        ->and($reuse->successful())->toBeFalse()
        ->and(array_map(static fn($event) => $event->type, $audit->events()))->toContain(
            AuthEventType::ACCESS_TOKEN_ISSUED,
            AuthEventType::REFRESH_TOKEN_ISSUED,
            AuthEventType::REFRESH_TOKEN_ROTATED,
            AuthEventType::REFRESH_TOKEN_REVOKED,
            AuthEventType::REFRESH_TOKEN_REUSE_DETECTED,
        );
});

it('surfaces token verification failures', function (): void {
    $refreshService = new TestRefreshTokenService();
    $refreshService->verifications['bad-token'] = new TokenVerificationResult(false, failureReason: 'expired_token');

    $manager = new TokenAuthManager(
        new TestAccessTokenService(),
        $refreshService,
        new InMemoryRefreshTokenStore(new FrozenClock(1000)),
        new InMemoryAuditEventStore(),
        new TestAuthIdGenerator(),
        300,
        new FrozenClock(1000),
    );

    $result = $manager->verifyRefreshToken('bad-token');

    expect($result->failed())->toBeTrue()
        ->and($result->code)->toBe('expired_token');
});

it('surfaces invalid and expired remember-me states', function (): void {
    $clock = new FrozenClock(1000);
    $tokens = new TestRememberTokenService();
    $store = new InMemoryRememberTokenStore($clock);
    $manager = new RememberMeManager($tokens, $store, new InMemoryAuditEventStore(), new TestAuthIdGenerator(), $clock);

    $issued = $manager->issue('acct-1', 'dev-1');
    $record = $issued->record;
    expect($record)->not->toBeNull();

    $tokens->verifications['missing-record'] = new RememberTokenVerificationResult(true, null);
    $missing = $manager->verify('missing-record');

    $clock->tick(86401);
    $tokens->verifications[$issued->token?->value ?? ''] = new RememberTokenVerificationResult(true, $record);
    $expired = $manager->verify($issued->token?->value ?? '');

    $familyRevokedRecord = $manager->issue('acct-1', 'dev-1')->record;
    expect($familyRevokedRecord)->not->toBeNull();
    $store->revokeFamily($familyRevokedRecord->familyId);
    $tokens->verifications['revoked-family'] = new RememberTokenVerificationResult(true, $familyRevokedRecord);
    $revokedFamily = $manager->verify('revoked-family');

    expect($missing->status)->toBe(RememberTokenStatus::INVALID)
        ->and($expired->status)->toBe(RememberTokenStatus::EXPIRED)
        ->and($revokedFamily->status)->toBe(RememberTokenStatus::INVALID);
});

it('handles refresh token family-revoked and stale-token rotation paths', function (): void {
    $clock = new FrozenClock(1000);
    $ids = new TestAuthIdGenerator();
    $audit = new InMemoryAuditEventStore();
    $store = new InMemoryRefreshTokenStore($clock);
    $manager = new TokenAuthManager(new TestAccessTokenService(), new TestRefreshTokenService(), $store, $audit, $ids, 60, $clock);

    $issued = $manager->issueRefreshToken('acct-1', 'client-1', 'dev-1');
    $record = $issued->refreshToken;
    expect($record)->not->toBeNull();

    $store->revokeFamily($record->familyId);
    $familyRevoked = $manager->rotateRefreshToken($record, ['session_id' => 'sess-1']);

    $freshIssue = $manager->issueRefreshToken('acct-1', 'client-1', 'dev-1');
    $freshRecord = $freshIssue->refreshToken;
    expect($freshRecord)->not->toBeNull();
    $clock->tick(61);
    $stale = $manager->rotateRefreshToken($freshRecord, ['device_id' => 'dev-1']);

    expect($familyRevoked->successful())->toBeFalse()
        ->and($familyRevoked->code)->toBe('refresh_token_family_revoked')
        ->and($stale->successful())->toBeFalse()
        ->and($stale->code)->toBe('refresh_token_reuse_detected')
        ->and(array_map(static fn($event) => $event->type, $audit->events()))->toContain(AuthEventType::REFRESH_TOKEN_REUSE_DETECTED);
});

it('surfaces access token verification failures', function (): void {
    $access = new TestAccessTokenService();
    $access->verifications['bad-access'] = new TokenVerificationResult(false, failureReason: 'bad_access_token');
    $manager = new TokenAuthManager(
        $access,
        new TestRefreshTokenService(),
        new InMemoryRefreshTokenStore(new FrozenClock(1000)),
        new InMemoryAuditEventStore(),
        new TestAuthIdGenerator(),
        300,
        new FrozenClock(1000),
    );

    $result = $manager->verifyAccessToken('bad-access');

    expect($result->failed())->toBeTrue()
        ->and($result->code)->toBe('bad_access_token');
});
