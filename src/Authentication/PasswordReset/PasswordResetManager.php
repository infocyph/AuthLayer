<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\PasswordReset;

use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Notification\AuthNotifierInterface;
use Infocyph\AuthLayer\Contract\Security\PasswordHasherInterface;
use Infocyph\AuthLayer\Contract\Security\PasswordPolicyInterface;
use Infocyph\AuthLayer\Contract\Security\TokenVerificationResult;
use Infocyph\AuthLayer\Contract\Storage\AccountStoreInterface;
use Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface;
use Infocyph\AuthLayer\Contract\Storage\PasswordResetStoreInterface;
use Infocyph\AuthLayer\Notification\AuthNotification;
use Infocyph\AuthLayer\Notification\AuthNotificationType;
use Infocyph\AuthLayer\Support\AuthEventRecorder;
use Infocyph\AuthLayer\Support\ContextValue;
use Infocyph\AuthLayer\Support\SystemClock;

final readonly class PasswordResetManager
{
    public function __construct(
        private PasswordResetTokenServiceInterface $tokens,
        private PasswordResetStoreInterface $store,
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
    public function complete(string $token, string $passwordHash, array $context = []): PasswordResetResult
    {
        $verification = $this->tokens->verify($token);

        if (!$verification->verified) {
            return new PasswordResetResult(PasswordResetStatus::INVALID, code: $verification->failureReason ?? 'invalid_token', context: $context);
        }

        $request = $this->resolveRequest($verification);

        if ($request === null) {
            return new PasswordResetResult(PasswordResetStatus::INVALID, code: 'reset_request_not_found', context: $context);
        }

        if ($request->isConsumed() || $this->store->wasConsumed($request->id)) {
            return new PasswordResetResult(PasswordResetStatus::CONSUMED, $request, code: 'reset_request_consumed', context: $context);
        }

        if ($request->isExpiredAt($this->clock->now())) {
            return new PasswordResetResult(PasswordResetStatus::EXPIRED, $request, code: 'reset_request_expired', context: $context);
        }

        $this->store->consume($request->id);
        $this->accounts->updatePasswordHash($request->accountId, $passwordHash);
        $this->recordEvent(AuthEventType::PASSWORD_RESET_COMPLETED, $request->accountId, $context, ['request_id' => $request->id], AuthEventSeverity::NOTICE);

        return new PasswordResetResult(PasswordResetStatus::COMPLETED, $request, code: 'password_reset_completed', context: $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function completeWithPlainPassword(
        string $token,
        string $plainPassword,
        PasswordHasherInterface $hasher,
        ?PasswordPolicyInterface $policy = null,
        array $context = [],
    ): PasswordResetResult {
        if ($policy !== null) {
            $policyResult = $policy->validate($plainPassword, $context);

            if (!$policyResult->valid) {
                return new PasswordResetResult(
                    PasswordResetStatus::POLICY_FAILED,
                    code: $policyResult->code ?? 'password_policy_failed',
                    context: ['violations' => $policyResult->violations] + $context,
                );
            }
        }

        return $this->complete($token, $hasher->hash($plainPassword, $context), $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function issue(string $accountId, array $context = []): PasswordResetResult
    {
        $now = $this->clock->now();
        $requestId = $this->ids->challengeId();
        $request = new PasswordResetRequest($requestId, $accountId, $now, $now + $this->ttlSeconds, context: $context);

        $this->store->save($request);
        $token = $this->tokens->issue($accountId, ['request_id' => $requestId] + $context);
        $this->notifier->send(new AuthNotification(AuthNotificationType::PASSWORD_RESET_REQUESTED, $accountId, ['request_id' => $requestId, 'token' => $token] + $context));
        $this->recordEvent(AuthEventType::PASSWORD_RESET_REQUESTED, $accountId, $context, ['request_id' => $requestId], AuthEventSeverity::NOTICE);

        return new PasswordResetResult(PasswordResetStatus::REQUESTED, $request, $token, 'password_reset_requested', $context);
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

    private function resolveRequest(TokenVerificationResult $verification): ?PasswordResetRequest
    {
        $requestId = $verification->claims['request_id'] ?? $verification->tokenId;

        if (!is_string($requestId) || $requestId === '') {
            return null;
        }

        return $this->store->find($requestId);
    }
}
