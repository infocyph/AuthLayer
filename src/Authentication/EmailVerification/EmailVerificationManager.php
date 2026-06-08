<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\EmailVerification;

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
use Infocyph\AuthLayer\Support\AuthEventRecorder;
use Infocyph\AuthLayer\Support\ContextValue;
use Infocyph\AuthLayer\Support\SystemClock;

final readonly class EmailVerificationManager
{
    private const string REQUEST_CONTEXT_KEY = 'request_id';

    public function __construct(
        private EmailVerificationTokenServiceInterface $tokens,
        private EmailVerificationStoreInterface $store,
        private AccountStoreInterface $accounts,
        private AuthNotifierInterface $notifier,
        private AuditEventStoreInterface $audit,
        private AuthIdGeneratorInterface $ids,
        private int $ttlSeconds = 3600,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public function issue(string $accountId, string $email, array $context = []): EmailVerificationResult
    {
        $now = $this->clock->now();
        $requestId = $this->ids->challengeId();
        $request = new EmailVerificationRequest($requestId, $accountId, $email, $now, $now + $this->ttlSeconds, context: $context);

        $this->store->save($request);
        $requestContext = [self::REQUEST_CONTEXT_KEY => $requestId];
        $token = $this->tokens->issue($accountId, $email, $requestContext + $context);
        $this->notifier->send(new AuthNotification(AuthNotificationType::EMAIL_VERIFICATION_REQUESTED, $accountId, ['email' => $email] + $requestContext + ['token' => $token] + $context));
        $this->recordEvent(AuthEventType::EMAIL_VERIFICATION_REQUESTED, $accountId, $context, ['email' => $email] + $requestContext, AuthEventSeverity::INFO);

        return new EmailVerificationResult(EmailVerificationStatus::ISSUED, $request, $token, 'email_verification_requested', $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function verify(string $token, array $context = []): EmailVerificationResult
    {
        $now = $this->clock->now();
        $verification = $this->tokens->verify($token);

        if (!$verification->verified) {
            return $this->invalidVerificationResult($verification->failureReason ?? 'invalid_token', $context);
        }

        $request = $this->resolveRequest($verification);

        if ($request === null) {
            return $this->missingVerificationResult($context);
        }

        if ($request->isConsumed()) {
            return $this->consumedVerificationResult($request, $context);
        }

        if ($request->isExpiredAt($now)) {
            return $this->expiredVerificationResult($request, $context);
        }

        return $this->completeVerification($request, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function completeVerification(EmailVerificationRequest $request, array $context): EmailVerificationResult
    {
        $this->store->consume($request->id);
        $this->accounts->markVerified($request->accountId, $this->clock->now());
        $this->recordEvent(
            AuthEventType::EMAIL_VERIFIED,
            $request->accountId,
            $context,
            [self::REQUEST_CONTEXT_KEY => $request->id, 'email' => $request->email],
            AuthEventSeverity::INFO,
        );

        return new EmailVerificationResult(EmailVerificationStatus::VERIFIED, $request, code: 'email_verified', context: $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function consumedVerificationResult(EmailVerificationRequest $request, array $context): EmailVerificationResult
    {
        return new EmailVerificationResult(EmailVerificationStatus::CONSUMED, $request, code: 'verification_already_consumed', context: $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function expiredVerificationResult(EmailVerificationRequest $request, array $context): EmailVerificationResult
    {
        return new EmailVerificationResult(EmailVerificationStatus::EXPIRED, $request, code: 'verification_expired', context: $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function invalidVerificationResult(string $reason, array $context): EmailVerificationResult
    {
        return new EmailVerificationResult(EmailVerificationStatus::INVALID, code: $reason, context: $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function missingVerificationResult(array $context): EmailVerificationResult
    {
        return new EmailVerificationResult(EmailVerificationStatus::INVALID, code: 'verification_request_not_found', context: $context);
    }

    /**
     * @param array<string, mixed> $context
     * @param array<string, mixed> $metadata
     */
    private function recordEvent(
        AuthEventType $type,
        string $accountId,
        array $context = [],
        array $metadata = [],
        AuthEventSeverity $severity = AuthEventSeverity::INFO,
    ): void {
        AuthEventRecorder::record(
            $this->audit,
            $this->ids,
            $this->clock,
            $type,
            $accountId,
            metadata: $metadata + $context,
            severity: $severity,
            sessionId: ContextValue::stringOrNull($context, 'session_id'),
            deviceId: ContextValue::stringOrNull($context, 'device_id'),
        );
    }

    private function resolveRequest(TokenVerificationResult $verification): ?EmailVerificationRequest
    {
        $requestId = $verification->claims[self::REQUEST_CONTEXT_KEY] ?? $verification->tokenId;

        if (!is_string($requestId) || $requestId === '') {
            return null;
        }

        return $this->store->find($requestId);
    }
}
