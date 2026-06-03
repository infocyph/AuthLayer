<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Notification;

use Infocyph\AuthLayer\Notification\AuthNotification;

interface AuthNotifierInterface
{
    public function send(AuthNotification $notification): void;
}
