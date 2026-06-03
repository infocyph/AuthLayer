<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\EmailVerification;

use Infocyph\AuthLayer\Audit\AuthEvent;
use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Notification\AuthNotifierInterface;
use Infocyph\AuthLayer\Contract\Security\TokenVerificationResult;
use Infocyph\AuthLayer\Contract\Storage\AccountStoreInterface;
use Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface;
use Infocyph\AuthLayer\Contract\Storage\EmailVerificationStoreInterface;
use Infocyph\AuthLayer\Notification\AuthNotification;
use Infocyph\AuthLayer\Notification\AuthNotificationType;
use Infocyph\AuthLayer\Support\SystemClock;

final readonly class EmailVerificationManager
{
    public function __construct(
        private EmailVerificationTokenServiceInterface $tokens,
        private EmailVerificationStoreInterface $store,
        private AccountStoreInterface $accounts,
        private AuthNotifierInterface $notifier,
        private AuditEventStoreInterface $audit,
        private AuthIdGeneratorInterface $ids,
        private int $ttlSeconds = 3600,
        private ClockInterface $clock = new SystemClock(),
    ) {
    }

    /**
     * @param array<string, mixed> $context
     */
    public function issue(string $accountId, string $email, array $context = []): EmailVerificationResult
    {
        $now = $this->clock->now();
        $requestId = $this->ids->challengeId();
        $request = new EmailVerificationRequest($requestId, $accountId, $email, $now, $now + $this->ttlSeconds, context: $context);

        $this->store->save($request);
        $token = $this->tokens->issue($accountId, $email, ['request_id' => $requestId] + $context);
        $this->notifier->send(new AuthNotification(AuthNotificationType::EMAIL_VERIFICATION_REQUESTED, $accountId, ['email' => $email, 'request_id' => $requestId, 'token' => $token] + $context));
        $this->audit->record(new AuthEvent(
            id: $this->ids->auditEventId(),
            type: AuthEventType::EMAIL_VERIFICATION_REQUESTED,
            severity: AuthEventSeverity::INFO,
            accountId: $accountId,
            actorId: $accountId,
            sessionId: $context['session_id'] ?? null,
            deviceId: $context['device_id'] ?? null,
            correlationId: $this->ids->correlationId(),
            occurredAt: $now,
            metadata: ['request_id' => $requestId, 'email' => $email] + $context,
        ));

        return new EmailVerificationResult(EmailVerificationStatus::ISSUED, $request, $token, 'email_verification_requested', $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function verify(string $token, array $context = []): EmailVerificationResult
    {
        $verification = $this->tokens->verify($token);

        if (! $verification->verified) {
            return new EmailVerificationResult(EmailVerificationStatus::INVALID, code: $verification->failureReason ?? 'invalid_token', context: $context);
        }

        $request = $this->resolveRequest($verification);

        if ($request === null) {
            return new EmailVerificationResult(EmailVerificationStatus::INVALID, code: 'verification_request_not_found', context: $context);
        }

        if ($request->isConsumed()) {
            return new EmailVerificationResult(EmailVerificationStatus::CONSUMED, $request, code: 'verification_already_consumed', context: $context);
        }

        if ($request->isExpiredAt($this->clock->now())) {
            return new EmailVerificationResult(EmailVerificationStatus::EXPIRED, $request, code: 'verification_expired', context: $context);
        }

        $this->store->consume($request->id);
        $this->accounts->markVerified($request->accountId, $this->clock->now());
        $this->audit->record(new AuthEvent(
            id: $this->ids->auditEventId(),
            type: AuthEventType::EMAIL_VERIFIED,
            severity: AuthEventSeverity::INFO,
            accountId: $request->accountId,
            actorId: $request->accountId,
            sessionId: $context['session_id'] ?? null,
            deviceId: $context['device_id'] ?? null,
            correlationId: $this->ids->correlationId(),
            occurredAt: $this->clock->now(),
            metadata: ['request_id' => $request->id, 'email' => $request->email] + $context,
        ));

        return new EmailVerificationResult(EmailVerificationStatus::VERIFIED, $request, code: 'email_verified', context: $context);
    }

    private function resolveRequest(TokenVerificationResult $verification): ?EmailVerificationRequest
    {
        $requestId = $verification->claims['request_id'] ?? $verification->tokenId;

        return is_string($requestId) && $requestId !== '' ? $this->store->find($requestId) : null;
    }
}
