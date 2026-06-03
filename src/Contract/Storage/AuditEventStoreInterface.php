<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Storage;

use Infocyph\AuthLayer\Audit\AuthEvent;

interface AuditEventStoreInterface
{
    public function record(AuthEvent $event): void;
}
