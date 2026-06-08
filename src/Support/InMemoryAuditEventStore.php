<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Audit\AuthEvent;
use Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface;

final class InMemoryAuditEventStore implements AuditEventStoreInterface
{
    /**
     * @var list<AuthEvent>
     */
    private array $events = [];

    /**
     * @return list<AuthEvent>
     */
    public function events(): array
    {
        return $this->events;
    }

    public function flush(): void
    {
        $this->events = [];
    }

    public function record(AuthEvent $event): void
    {
        $this->events[] = $event;
    }
}
