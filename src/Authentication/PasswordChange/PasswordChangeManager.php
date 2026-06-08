<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\PasswordChange;

use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Notification\AuthNotifierInterface;
use Infocyph\AuthLayer\Contract\Security\PasswordHasherInterface;
use Infocyph\AuthLayer\Contract\Security\PasswordPolicyInterface;
use Infocyph\AuthLayer\Contract\Security\PasswordVerifierInterface;
use Infocyph\AuthLayer\Contract\Storage\AccountProviderInterface;
use Infocyph\AuthLayer\Contract\Storage\AccountStoreInterface;
use Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface;
use Infocyph\AuthLayer\Notification\AuthNotification;
use Infocyph\AuthLayer\Notification\AuthNotificationType;
use Infocyph\AuthLayer\Support\AuthEventRecorder;
use Infocyph\AuthLayer\Support\ContextValue;
use Infocyph\AuthLayer\Support\SystemClock;

final readonly class PasswordChangeManager
{
    public function __construct(
        private AccountProviderInterface $accounts,
        private AccountStoreInterface $accountStore,
        private PasswordVerifierInterface $passwords,
        private AuditEventStoreInterface $audit,
        private AuthNotifierInterface $notifier,
        private AuthIdGeneratorInterface $ids,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public function change(string $accountId, string $currentPassword, string $newPasswordHash, array $context = []): PasswordChangeResult
    {
        $account = $this->accounts->findById($accountId);

        if ($account === null || $account->passwordHash() === null) {
            return new PasswordChangeResult(PasswordChangeStatus::ACCOUNT_NOT_FOUND, 'account_not_found', $context);
        }

        $verification = $this->passwords->verify($currentPassword, $account->passwordHash());

        if (!$verification->verified) {
            return new PasswordChangeResult(PasswordChangeStatus::INVALID_CREDENTIALS, 'invalid_credentials', $context);
        }

        $this->accountStore->updatePasswordHash($accountId, $newPasswordHash);
        AuthEventRecorder::record(
            $this->audit,
            $this->ids,
            $this->clock,
            AuthEventType::PASSWORD_CHANGED,
            $accountId,
            metadata: $context,
            severity: AuthEventSeverity::NOTICE,
            sessionId: ContextValue::stringOrNull($context, 'session_id'),
            deviceId: ContextValue::stringOrNull($context, 'device_id'),
        );
        $this->notifier->send(new AuthNotification(AuthNotificationType::PASSWORD_CHANGED, $accountId, $context));

        return new PasswordChangeResult(PasswordChangeStatus::CHANGED, 'password_changed', $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function changeWithPlainPassword(
        string $accountId,
        string $currentPassword,
        string $newPlainPassword,
        PasswordHasherInterface $hasher,
        ?PasswordPolicyInterface $policy = null,
        array $context = [],
    ): PasswordChangeResult {
        if ($policy !== null) {
            $policyResult = $policy->validate($newPlainPassword, $context);

            if (!$policyResult->valid) {
                return new PasswordChangeResult(
                    PasswordChangeStatus::POLICY_FAILED,
                    $policyResult->code ?? 'password_policy_failed',
                    ['violations' => $policyResult->violations] + $context,
                );
            }
        }

        return $this->change($accountId, $currentPassword, $hasher->hash($newPlainPassword, $context), $context);
    }
}
