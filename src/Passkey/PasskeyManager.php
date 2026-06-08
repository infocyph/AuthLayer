<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Passkey;

use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Notification\AuthNotifierInterface;
use Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface;
use Infocyph\AuthLayer\Notification\AuthNotification;
use Infocyph\AuthLayer\Notification\AuthNotificationType;
use Infocyph\AuthLayer\Support\AuthEventRecorder;
use Infocyph\AuthLayer\Support\ContextValue;
use Infocyph\AuthLayer\Support\SystemClock;

final readonly class PasskeyManager
{
    public function __construct(
        private PasskeyServiceInterface $service,
        private PasskeyCredentialStoreInterface $credentials,
        private AuditEventStoreInterface $audit,
        private AuthNotifierInterface $notifier,
        private AuthIdGeneratorInterface $ids,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public function finishAuthentication(PasskeyAuthenticationResult $result, array $context = []): PasskeyAuthenticationOutcome
    {
        $verification = $this->service->finishAuthentication($result);

        if ($verification->verified && $verification->accountId !== null) {
            if ($verification->credentialId !== null && $verification->signCount !== null) {
                $this->credentials->updateUsage($verification->credentialId, $verification->signCount, $this->clock->now());
            }

            $this->record(AuthEventType::PASSKEY_USED, $verification->accountId, ['credential_id' => $verification->credentialId] + $context);
        }

        return new PasskeyAuthenticationOutcome(
            $verification->verified ? PasskeyAuthenticationStatus::VERIFIED : PasskeyAuthenticationStatus::INVALID,
            verification: $verification,
            code: $verification->verified ? 'passkey_verified' : ($verification->reason ?? 'passkey_invalid'),
            context: $context,
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    public function finishRegistration(PasskeyRegistrationResult $result, array $context = []): PasskeyRegistrationOutcome
    {
        $credential = $this->service->finishRegistration($result);
        $this->credentials->save($credential);
        $this->record(AuthEventType::PASSKEY_REGISTERED, $credential->accountId, ['credential_id' => $credential->id] + $context, AuthEventSeverity::NOTICE);
        $this->notifier->send(new AuthNotification(AuthNotificationType::PASSKEY_REGISTERED, $credential->accountId, ['credential_id' => $credential->id] + $context));

        return new PasskeyRegistrationOutcome(PasskeyRegistrationStatus::REGISTERED, credential: $credential, code: 'passkey_registered', context: $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function revokeCredential(string $accountId, string $credentialId, array $context = []): void
    {
        $this->credentials->revoke($credentialId);
        $this->record(AuthEventType::PASSKEY_REMOVED, $accountId, ['credential_id' => $credentialId] + $context, AuthEventSeverity::NOTICE);
        $this->notifier->send(new AuthNotification(AuthNotificationType::PASSKEY_REMOVED, $accountId, ['credential_id' => $credentialId] + $context));
    }

    /**
     * @param array<string, mixed> $context
     */
    public function startAuthentication(?string $accountId = null, array $context = []): PasskeyAuthenticationOutcome
    {
        $challenge = $this->service->startAuthentication($accountId);

        return new PasskeyAuthenticationOutcome(PasskeyAuthenticationStatus::STARTED, $challenge, code: 'passkey_authentication_started', context: $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function startRegistration(string $accountId, array $context = []): PasskeyRegistrationOutcome
    {
        $challenge = $this->service->startRegistration($accountId);

        return new PasskeyRegistrationOutcome(PasskeyRegistrationStatus::STARTED, $challenge, code: 'passkey_registration_started', context: $context);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function record(AuthEventType $type, string $accountId, array $metadata = [], AuthEventSeverity $severity = AuthEventSeverity::INFO): void
    {
        AuthEventRecorder::record(
            $this->audit,
            $this->ids,
            $this->clock,
            $type,
            $accountId,
            metadata: $metadata,
            severity: $severity,
            sessionId: ContextValue::stringOrNull($metadata, 'session_id'),
            deviceId: ContextValue::stringOrNull($metadata, 'device_id'),
        );
    }
}
