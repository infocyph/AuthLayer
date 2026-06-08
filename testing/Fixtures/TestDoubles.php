<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Tests\Fixtures;

use Infocyph\AuthLayer\Authentication\EmailVerification\EmailVerificationTokenServiceInterface;
use Infocyph\AuthLayer\Authentication\Passwordless\PasswordlessTokenServiceInterface;
use Infocyph\AuthLayer\Authentication\PasswordReset\PasswordResetTokenServiceInterface;
use Infocyph\AuthLayer\Authentication\RememberMe\RememberToken;
use Infocyph\AuthLayer\Authentication\RememberMe\RememberTokenServiceInterface;
use Infocyph\AuthLayer\Authentication\RememberMe\RememberTokenVerificationResult;
use Infocyph\AuthLayer\Authentication\TokenAuth\AccessTokenClaims;
use Infocyph\AuthLayer\Authentication\TokenAuth\IssuedRefreshToken;
use Infocyph\AuthLayer\Authentication\TokenAuth\RefreshTokenClaims;
use Infocyph\AuthLayer\Authentication\TokenAuth\RefreshTokenServiceInterface;
use Infocyph\AuthLayer\Authorization\Decision\AuthorizationDecision;
use Infocyph\AuthLayer\Authorization\Policy\PolicyInterface;
use Infocyph\AuthLayer\Authorization\Policy\PolicyResolverInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Security\AccessTokenServiceInterface;
use Infocyph\AuthLayer\Contract\Security\PasswordHasherInterface;
use Infocyph\AuthLayer\Contract\Security\PasswordPolicyInterface;
use Infocyph\AuthLayer\Contract\Security\PasswordPolicyResult;
use Infocyph\AuthLayer\Contract\Security\PasswordVerificationResult;
use Infocyph\AuthLayer\Contract\Security\PasswordVerifierInterface;
use Infocyph\AuthLayer\Contract\Security\TokenVerificationResult;
use Infocyph\AuthLayer\Mfa\MfaChallenge;
use Infocyph\AuthLayer\Mfa\MfaVerificationResult;
use Infocyph\AuthLayer\Mfa\MfaVerifierInterface;
use Infocyph\AuthLayer\Mfa\RecoveryCodeServiceInterface;
use Infocyph\AuthLayer\Mfa\RecoveryCodeVerificationResult;
use Infocyph\AuthLayer\Passkey\PasskeyAuthenticationResult;
use Infocyph\AuthLayer\Passkey\PasskeyChallenge;
use Infocyph\AuthLayer\Passkey\PasskeyCredential;
use Infocyph\AuthLayer\Passkey\PasskeyRegistrationResult;
use Infocyph\AuthLayer\Passkey\PasskeyServiceInterface;
use Infocyph\AuthLayer\Passkey\PasskeyVerificationResult;
use Infocyph\AuthLayer\Principal\PrincipalInterface;

final class TestAuthIdGenerator implements AuthIdGeneratorInterface
{
    /** @var array<string, int> */
    private array $counters = [];

    public function accountId(): string
    {
        return $this->next('acct');
    }

    public function auditEventId(): string
    {
        return $this->next('evt');
    }

    public function challengeId(): string
    {
        return $this->next('chl');
    }

    public function correlationId(): string
    {
        return $this->next('corr');
    }

    public function credentialId(): string
    {
        return $this->next('cred');
    }

    public function deviceId(): string
    {
        return $this->next('dev');
    }

    public function grantId(): string
    {
        return $this->next('grant');
    }

    public function permissionId(): string
    {
        return $this->next('perm');
    }

    public function roleId(): string
    {
        return $this->next('role');
    }

    public function sessionId(): string
    {
        return $this->next('sess');
    }

    private function next(string $prefix): string
    {
        $this->counters[$prefix] = ($this->counters[$prefix] ?? 0) + 1;

        return sprintf('%s-%d', $prefix, $this->counters[$prefix]);
    }
}

final class TestPasswordVerifier implements PasswordVerifierInterface
{
    public bool $needsRehash = false;

    public ?string $rehash = null;

    public ?PasswordVerificationResult $result = null;

    public function verify(string $plainPassword, string $storedHash): PasswordVerificationResult
    {
        if ($this->result instanceof PasswordVerificationResult) {
            return $this->result;
        }

        return new PasswordVerificationResult($plainPassword === $storedHash, $this->needsRehash, $this->rehash);
    }
}

final readonly class TestPasswordHasher implements PasswordHasherInterface
{
    public function __construct(
        private string $prefix = 'hashed:',
    ) {}

    public function hash(string $plainPassword, array $_context = []): string
    {
        unset($_context);

        return $this->prefix . $plainPassword;
    }
}

final readonly class TestPasswordPolicy implements PasswordPolicyInterface
{
    /**
     * @param list<string> $violations
     */
    public function __construct(
        private bool $valid = true,
        private array $violations = [],
        private ?string $code = null,
    ) {}

    public function validate(string $plainPassword, array $context = []): PasswordPolicyResult
    {
        unset($plainPassword, $context);

        return new PasswordPolicyResult($this->valid, $this->violations, $this->code);
    }
}

abstract class AbstractIssuedTokenService
{
    /** @var list<array<string, mixed>> */
    public array $issued = [];

    /** @var array<string, TokenVerificationResult> */
    public array $verifications = [];

    private int $counter = 0;

    protected function defaultToken(string $prefix): string
    {
        $this->counter++;

        return sprintf('%s-%d', $prefix, $this->counter);
    }

    /**
     * @param array<string, mixed> $payload
     * @param array<string, mixed> $claims
     */
    protected function issueToken(
        string $prefix,
        string $subjectId,
        array $payload,
        array $claims = [],
    ): string {
        $token = $this->defaultToken($prefix);
        $payload['token'] = $token;
        $this->issued[] = $payload;
        $this->verifications[$token] ??= new TokenVerificationResult(true, subjectId: $subjectId, claims: $claims);

        return $token;
    }

    protected function verifyToken(string $token): TokenVerificationResult
    {
        return $this->verifications[$token] ?? new TokenVerificationResult(false, failureReason: 'invalid_token');
    }
}

final class TestPasswordResetTokenService extends AbstractIssuedTokenService implements PasswordResetTokenServiceInterface
{
    public function issue(string $accountId, array $context = []): string
    {
        return $this->issueToken('reset-token', $accountId, ['account_id' => $accountId, 'context' => $context], $context);
    }

    public function verify(string $token): TokenVerificationResult
    {
        return $this->verifyToken($token);
    }
}

final class TestEmailVerificationTokenService extends AbstractIssuedTokenService implements EmailVerificationTokenServiceInterface
{
    public function issue(string $accountId, string $email, array $context = []): string
    {
        return $this->issueToken('verify-token', $accountId, ['account_id' => $accountId, 'email' => $email, 'context' => $context], $context);
    }

    public function verify(string $token): TokenVerificationResult
    {
        return $this->verifyToken($token);
    }
}

final class TestPasswordlessTokenService extends AbstractIssuedTokenService implements PasswordlessTokenServiceInterface
{
    public function issue(string $identifier, array $context = []): string
    {
        return $this->issueToken('passwordless-token', $identifier, ['identifier' => $identifier, 'context' => $context], $context);
    }

    public function verify(string $token): TokenVerificationResult
    {
        return $this->verifyToken($token);
    }
}

final class TestAccessTokenService extends AbstractIssuedTokenService implements AccessTokenServiceInterface
{
    /** @var list<AccessTokenClaims> */
    public array $claims = [];

    public function issue(AccessTokenClaims $claims): string
    {
        $token = $this->defaultToken('access-token');
        $this->claims[] = $claims;
        $this->verifications[$token] ??= new TokenVerificationResult(true, subjectId: $claims->subjectId, claims: ['scopes' => $claims->scopes] + $claims->metadata, expiresAt: $claims->expiresAt);

        return $token;
    }

    public function verify(string $token): TokenVerificationResult
    {
        return $this->verifyToken($token);
    }
}

final class TestRememberTokenService implements RememberTokenServiceInterface
{
    public int $expiresAt = 86400;

    /** @var list<RememberToken> */
    public array $issued = [];

    /** @var array<string, RememberTokenVerificationResult> */
    public array $verifications = [];

    private int $counter = 0;

    public function issue(string $_accountId, string $_deviceId): RememberToken
    {
        unset($_accountId, $_deviceId);
        $this->counter++;
        $token = new RememberToken(
            value: sprintf('remember-token-%d', $this->counter),
            selector: sprintf('selector-%d', $this->counter),
            familyId: sprintf('family-%d', $this->counter),
            verifierHash: sprintf('verifier-hash-%d', $this->counter),
            expiresAt: $this->expiresAt,
        );

        $this->issued[] = $token;

        return $token;
    }

    public function verify(string $token): RememberTokenVerificationResult
    {
        return $this->verifications[$token] ?? new RememberTokenVerificationResult(false, failureReason: 'invalid_remember_token');
    }
}

final class TestRefreshTokenService extends AbstractIssuedTokenService implements RefreshTokenServiceInterface
{
    /** @var list<RefreshTokenClaims> */
    public array $claims = [];

    public function issue(RefreshTokenClaims $claims): IssuedRefreshToken
    {
        $value = $this->defaultToken('refresh-token');
        $this->claims[] = $claims;
        $this->verifications[$value] ??= new TokenVerificationResult(true, subjectId: $claims->accountId, tokenId: $claims->tokenId, claims: $claims->metadata, expiresAt: $claims->expiresAt);

        return new IssuedRefreshToken(
            value: $value,
            tokenHash: 'hash:' . $value,
            tokenId: $claims->tokenId,
            familyId: $claims->familyId,
            expiresAt: $claims->expiresAt,
        );
    }

    public function verify(string $token): TokenVerificationResult
    {
        return $this->verifyToken($token);
    }
}

final class TestMfaVerifier implements MfaVerifierInterface
{
    public ?MfaVerificationResult $result = null;

    public function verify(MfaChallenge $challenge, string $code): MfaVerificationResult
    {
        if ($this->result instanceof MfaVerificationResult) {
            return $this->result;
        }

        return new MfaVerificationResult($code === '123456', factorId: $challenge->factorId);
    }
}

final class TestRecoveryCodeService implements RecoveryCodeServiceInterface
{
    /** @var list<string> */
    public array $generated = [];

    /** @var array<string, RecoveryCodeVerificationResult> */
    public array $verificationMap = [];

    public function generate(string $accountId, int $count = 10): array
    {
        unset($accountId);
        $this->generated = array_map(
            static fn(int $index): string => sprintf('recovery-%d', $index),
            range(1, $count),
        );

        return $this->generated;
    }

    public function verify(string $accountId, string $code): RecoveryCodeVerificationResult
    {
        unset($accountId);

        return $this->verificationMap[$code] ?? new RecoveryCodeVerificationResult(in_array($code, $this->generated, true), $code === 'invalid' ? 'invalid_recovery_code' : null);
    }
}

final class TestPasskeyService implements PasskeyServiceInterface
{
    public ?PasskeyChallenge $authenticationChallenge = null;

    public ?PasskeyCredential $credential = null;

    public ?PasskeyChallenge $registrationChallenge = null;

    public ?PasskeyVerificationResult $verification = null;

    public function finishAuthentication(PasskeyAuthenticationResult $result): PasskeyVerificationResult
    {
        return $this->verification ?? new PasskeyVerificationResult(true, accountId: 'acct-1', credentialId: $result->credentialId, signCount: 1);
    }

    public function finishRegistration(PasskeyRegistrationResult $result): PasskeyCredential
    {
        return $this->credential ?? new PasskeyCredential(
            id: 'cred-record-1',
            accountId: $result->accountId,
            credentialId: $result->credentialId,
            publicKey: $result->publicKey,
            signCount: $result->signCount,
            transports: $result->transports,
            createdAt: 1000,
            metadata: $result->metadata,
        );
    }

    public function startAuthentication(?string $accountId = null): PasskeyChallenge
    {
        return $this->authenticationChallenge ?? new PasskeyChallenge('pk-auth-1', $accountId, 'login', 'challenge-auth', 1000, 1300);
    }

    public function startRegistration(string $accountId): PasskeyChallenge
    {
        return $this->registrationChallenge ?? new PasskeyChallenge('pk-reg-1', $accountId, 'registration', 'challenge-reg', 1000, 1300);
    }
}

final readonly class TestPolicy implements PolicyInterface
{
    /**
     * @param array<string, AuthorizationDecision|bool|null> $decisions
     */
    public function __construct(
        private array $decisions = [],
        private AuthorizationDecision|bool|null $defaultDecision = null,
    ) {}

    public function authorize(PrincipalInterface $principal, string $ability, mixed $resource = null, array $context = []): AuthorizationDecision|bool|null
    {
        unset($principal, $resource, $context);

        if (array_key_exists($ability, $this->decisions)) {
            return $this->decisions[$ability];
        }

        return $this->defaultDecision;
    }
}

final readonly class TestPolicyResolver implements PolicyResolverInterface
{
    public function __construct(
        private ?PolicyInterface $policy = null,
    ) {}

    public function resolve(mixed $resource): ?PolicyInterface
    {
        unset($resource);

        return $this->policy;
    }
}
