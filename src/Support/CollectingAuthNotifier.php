<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Contract\Notification\AuthNotifierInterface;
use Infocyph\AuthLayer\Notification\AuthNotification;

final class CollectingAuthNotifier implements AuthNotifierInterface
{
    /**
     * @var list<AuthNotification>
     */
    private array $notifications = [];

    public function send(AuthNotification $notification): void
    {
        $this->notifications[] = $notification;
    }

    /**
     * @return list<AuthNotification>
     */
    public function notifications(): array
    {
        return $this->notifications;
    }

    public function flush(): void
    {
        $this->notifications = [];
    }
}
