<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Contract\Notification\AuthNotifierInterface;
use Infocyph\AuthLayer\Notification\AuthNotification;

final class NullAuthNotifier implements AuthNotifierInterface
{
    public function send(AuthNotification $notification): void {}
}
