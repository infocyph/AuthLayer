<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Event;

interface EventDispatcherInterface
{
    public function dispatch(object $event): void;
}
