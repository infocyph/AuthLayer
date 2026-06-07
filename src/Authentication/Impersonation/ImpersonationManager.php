<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Impersonation;

use Infocyph\AuthLayer\Account\AccountInterface;
use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface;
use Infocyph\AuthLayer\Principal\Principal;
use Infocyph\AuthLayer\Principal\PrincipalInterface;
use Infocyph\AuthLayer\Principal\PrincipalType;
use Infocyph\AuthLayer\Support\AuthEventRecorder;
use Infocyph\AuthLayer\Support\ContextValue;
use Infocyph\AuthLayer\Support\SystemClock;

final readonly class ImpersonationManager
{
    public function __construct(
        private AuditEventStoreInterface $audit,
        private AuthIdGeneratorInterface $ids,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public function startImpersonation(PrincipalInterface $actor, AccountInterface $target, array $context = []): ImpersonationResult
    {
        $session = new ImpersonationSession($actor->id(), $target->id(), $this->clock->now(), $context);
        $principal = new Principal(
            id: $target->id(),
            type: PrincipalType::IMPERSONATED,
            accountId: $target->id(),
            metadata: ['impersonator_id' => $actor->id()] + $target->metadata(),
        );

        $this->record(AuthEventType::IMPERSONATION_STARTED, $target->id(), $actor->id(), ['target_account_id' => $target->id()] + $context);

        return new ImpersonationResult($principal, $session, 'impersonation_started', $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function stopImpersonation(ImpersonationSession $session, array $context = []): ImpersonationResult
    {
        $principal = new Principal(
            id: $session->actorId,
            type: PrincipalType::ACCOUNT,
            accountId: $session->actorId,
            metadata: $context,
        );

        $this->record(AuthEventType::IMPERSONATION_STOPPED, $session->targetAccountId, $session->actorId, ['target_account_id' => $session->targetAccountId] + $context);

        return new ImpersonationResult($principal, $session, 'impersonation_stopped', $context);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function record(AuthEventType $type, string $accountId, string $actorId, array $metadata): void
    {
        AuthEventRecorder::record(
            $this->audit,
            $this->ids,
            $this->clock,
            $type,
            $accountId,
            actorId: $actorId,
            metadata: $metadata,
            severity: AuthEventSeverity::NOTICE,
            sessionId: ContextValue::stringOrNull($metadata, 'session_id'),
            deviceId: ContextValue::stringOrNull($metadata, 'device_id'),
        );
    }
}
