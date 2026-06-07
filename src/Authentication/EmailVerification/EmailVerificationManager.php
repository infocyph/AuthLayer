<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\EmailVerification;

use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Authentication\Support\AbstractTokenRequestManager;
use Infocyph\AuthLayer\Contract\Security\TokenVerificationResult as VerifiedToken;
use Infocyph\AuthLayer\Contract\Storage\EmailVerificationStoreInterface as VerificationStore;
use Infocyph\AuthLayer\Notification\AuthNotification;
use Infocyph\AuthLayer\Notification\AuthNotificationType;
use Infocyph\AuthLayer\Support\ConsumableTokenRequestProcessor;

final readonly class EmailVerificationManager extends AbstractTokenRequestManager
{
    private const string REQUEST_CONTEXT_KEY = 'request_id';

    public function __construct(
        private EmailVerificationTokenServiceInterface $tokens,
        private VerificationStore $store,
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

        return ConsumableTokenRequestProcessor::process(
            verification: $this->tokens->verify($token),
            resolveRequest: $this->resolveRequest(...),
            invalidResult: fn(string $reason): EmailVerificationResult => $this->invalidVerificationResult($reason, $context),
            missingRequestResult: fn(): EmailVerificationResult => $this->missingVerificationResult($context),
            isConsumed: static fn(EmailVerificationRequest $request): bool => $request->isConsumed(),
            consumedResult: fn(EmailVerificationRequest $request): EmailVerificationResult => $this->consumedVerificationResult($request, $context),
            isExpired: static fn(EmailVerificationRequest $request): bool => $request->isExpiredAt($now),
            expiredResult: fn(EmailVerificationRequest $request): EmailVerificationResult => $this->expiredVerificationResult($request, $context),
            successResult: fn(EmailVerificationRequest $request): EmailVerificationResult => $this->completeVerification($request, $context),
        );
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

    private function resolveRequest(VerifiedToken $verification): ?EmailVerificationRequest
    {
        $requestId = $this->resolveRequestId($verification);

        return $requestId !== null ? $this->store->find($requestId) : null;
    }
}
