<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\PasswordReset;

use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Authentication\Support\AbstractTokenRequestManager;
use Infocyph\AuthLayer\Contract\Security\PasswordHasherInterface;
use Infocyph\AuthLayer\Contract\Security\PasswordPolicyInterface;
use Infocyph\AuthLayer\Contract\Security\TokenVerificationResult;
use Infocyph\AuthLayer\Contract\Storage\PasswordResetStoreInterface;
use Infocyph\AuthLayer\Notification\AuthNotification;
use Infocyph\AuthLayer\Notification\AuthNotificationType;
use Infocyph\AuthLayer\Support\ConsumableTokenRequestProcessor;

final readonly class PasswordResetManager extends AbstractTokenRequestManager
{
    public function __construct(
        private PasswordResetTokenServiceInterface $tokens,
        private PasswordResetStoreInterface $store,
        \Infocyph\AuthLayer\Contract\Storage\AccountStoreInterface $accounts,
        \Infocyph\AuthLayer\Contract\Notification\AuthNotifierInterface $notifier,
        \Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface $audit,
        \Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface $ids,
        int $ttlSeconds = 3600,
        \Infocyph\AuthLayer\Contract\Clock\ClockInterface $clock = new \Infocyph\AuthLayer\Support\SystemClock(),
    ) {
        parent::__construct($accounts, $notifier, $audit, $ids, $ttlSeconds, $clock);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function complete(string $token, string $passwordHash, array $context = []): PasswordResetResult
    {
        return ConsumableTokenRequestProcessor::process(
            verification: $this->tokens->verify($token),
            resolveRequest: $this->resolveRequest(...),
            invalidResult: static fn(string $reason): PasswordResetResult => new PasswordResetResult(PasswordResetStatus::INVALID, code: $reason, context: $context),
            missingRequestResult: static fn(): PasswordResetResult => new PasswordResetResult(PasswordResetStatus::INVALID, code: 'reset_request_not_found', context: $context),
            isConsumed: fn(PasswordResetRequest $request): bool => $request->isConsumed() || $this->store->wasConsumed($request->id),
            consumedResult: static fn(PasswordResetRequest $request): PasswordResetResult => new PasswordResetResult(PasswordResetStatus::CONSUMED, $request, code: 'reset_request_consumed', context: $context),
            isExpired: fn(PasswordResetRequest $request): bool => $request->isExpiredAt($this->clock->now()),
            expiredResult: static fn(PasswordResetRequest $request): PasswordResetResult => new PasswordResetResult(PasswordResetStatus::EXPIRED, $request, code: 'reset_request_expired', context: $context),
            successResult: function (PasswordResetRequest $request) use ($context, $passwordHash): PasswordResetResult {
                $this->store->consume($request->id);
                $this->accounts->updatePasswordHash($request->accountId, $passwordHash);
                $this->recordEvent(AuthEventType::PASSWORD_RESET_COMPLETED, $request->accountId, $context, ['request_id' => $request->id], AuthEventSeverity::NOTICE);

                return new PasswordResetResult(PasswordResetStatus::COMPLETED, $request, code: 'password_reset_completed', context: $context);
            },
        );
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

    private function resolveRequest(TokenVerificationResult $verification): ?PasswordResetRequest
    {
        $requestId = $this->resolveRequestId($verification);

        return $requestId !== null ? $this->store->find($requestId) : null;
    }
}
