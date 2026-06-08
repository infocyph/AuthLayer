<?php

declare(strict_types=1);

use Infocyph\AuthLayer\Account\AccountActionStatus;
use Infocyph\AuthLayer\Account\AccountResult;
use Infocyph\AuthLayer\Authentication\EmailVerification\EmailVerificationResult;
use Infocyph\AuthLayer\Authentication\EmailVerification\EmailVerificationStatus;
use Infocyph\AuthLayer\Authentication\Impersonation\ImpersonationResult;
use Infocyph\AuthLayer\Authentication\Impersonation\ImpersonationSession;
use Infocyph\AuthLayer\Authentication\Lockout\LockoutResult;
use Infocyph\AuthLayer\Authentication\Lockout\LockoutStatus;
use Infocyph\AuthLayer\Authentication\Login\LoginResult;
use Infocyph\AuthLayer\Authentication\Login\LoginStatus;
use Infocyph\AuthLayer\Authentication\PasswordChange\PasswordChangeResult;
use Infocyph\AuthLayer\Authentication\PasswordChange\PasswordChangeStatus;
use Infocyph\AuthLayer\Authentication\PasswordReset\PasswordResetResult;
use Infocyph\AuthLayer\Authentication\PasswordReset\PasswordResetStatus;
use Infocyph\AuthLayer\Authentication\Passwordless\PasswordlessResult;
use Infocyph\AuthLayer\Authentication\Passwordless\PasswordlessStatus;
use Infocyph\AuthLayer\Authentication\RememberMe\RememberMeResult;
use Infocyph\AuthLayer\Authentication\RememberMe\RememberTokenStatus;
use Infocyph\AuthLayer\Authentication\StepUp\StepUpMethod;
use Infocyph\AuthLayer\Authentication\StepUp\StepUpRequirement;
use Infocyph\AuthLayer\Authentication\StepUp\StepUpResult;
use Infocyph\AuthLayer\Authentication\TokenAuth\RefreshTokenRotationResult;
use Infocyph\AuthLayer\Authentication\TokenAuth\TokenAuthResult;
use Infocyph\AuthLayer\Authentication\TokenAuth\TokenRevocationResult;
use Infocyph\AuthLayer\Authentication\TokenAuth\TokenRevocationStatus;
use Infocyph\AuthLayer\Authentication\TokenAuth\TokenType;
use Infocyph\AuthLayer\Authorization\Grant\DelegationResult;
use Infocyph\AuthLayer\Authorization\Grant\DelegationStatus;
use Infocyph\AuthLayer\Device\DeviceResult;
use Infocyph\AuthLayer\Device\DeviceStatus;
use Infocyph\AuthLayer\Mfa\MfaChallengeResult;
use Infocyph\AuthLayer\Mfa\MfaEnrollmentResult;
use Infocyph\AuthLayer\Mfa\MfaStatus;
use Infocyph\AuthLayer\Passkey\PasskeyAuthenticationOutcome;
use Infocyph\AuthLayer\Passkey\PasskeyAuthenticationStatus;
use Infocyph\AuthLayer\Passkey\PasskeyRegistrationOutcome;
use Infocyph\AuthLayer\Passkey\PasskeyRegistrationStatus;
use Infocyph\AuthLayer\Principal\Principal;
use Infocyph\AuthLayer\Principal\PrincipalType;

it('exposes consistent successful and failed helpers across result objects', function (): void {
    $principal = new Principal('acct-1', PrincipalType::ACCOUNT, 'acct-1');
    $session = new ImpersonationSession('admin-1', 'acct-1', 1000);

    expect((new AccountResult(AccountActionStatus::CREATED))->successful())->toBeTrue()
        ->and((new PasswordChangeResult(PasswordChangeStatus::CHANGED))->successful())->toBeTrue()
        ->and((new PasswordResetResult(PasswordResetStatus::COMPLETED))->successful())->toBeTrue()
        ->and((new EmailVerificationResult(EmailVerificationStatus::VERIFIED))->successful())->toBeTrue()
        ->and((new RememberMeResult(RememberTokenStatus::VERIFIED))->successful())->toBeTrue()
        ->and((new TokenRevocationResult(TokenRevocationStatus::REVOKED, 'family-1'))->successful())->toBeTrue()
        ->and((new MfaEnrollmentResult(MfaStatus::ENROLLED))->successful())->toBeTrue()
        ->and((new MfaChallengeResult(MfaStatus::VERIFIED))->successful())->toBeTrue()
        ->and((new PasskeyRegistrationOutcome(PasskeyRegistrationStatus::REGISTERED))->successful())->toBeTrue()
        ->and((new PasskeyAuthenticationOutcome(PasskeyAuthenticationStatus::VERIFIED))->successful())->toBeTrue()
        ->and((new DelegationResult(DelegationStatus::GRANTED))->successful())->toBeTrue()
        ->and((new DeviceResult(DeviceStatus::REGISTERED))->successful())->toBeTrue()
        ->and((new LoginResult(LoginStatus::AUTHENTICATED, $principal))->successful())->toBeTrue()
        ->and((new PasswordlessResult(PasswordlessStatus::VERIFIED))->successful())->toBeTrue()
        ->and((new LockoutResult(LockoutStatus::LOCKED, 'acct-1'))->successful())->toBeTrue()
        ->and((new ImpersonationResult($principal, $session))->successful())->toBeTrue()
        ->and((new StepUpResult(false, new StepUpRequirement('billing:update', 900, StepUpMethod::MFA)))->successful())->toBeTrue()
        ->and((new TokenAuthResult(TokenType::ACCESS, 'token'))->successful())->toBeTrue()
        ->and((new RefreshTokenRotationResult(true))->successful())->toBeTrue();
});

it('reports failed helpers for unsuccessful results', function (): void {
    expect((new PasswordChangeResult(PasswordChangeStatus::INVALID_CREDENTIALS))->failed())->toBeTrue()
        ->and((new EmailVerificationResult(EmailVerificationStatus::INVALID))->failed())->toBeTrue()
        ->and((new PasswordlessResult(PasswordlessStatus::INVALID))->failed())->toBeTrue()
        ->and((new StepUpResult(true, new StepUpRequirement('billing:update')))->failed())->toBeTrue()
        ->and((new RefreshTokenRotationResult(false))->failed())->toBeTrue();
});
