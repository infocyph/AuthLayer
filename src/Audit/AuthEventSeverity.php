<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Audit;

enum AuthEventSeverity: string
{
    case INFO = 'info';
    case NOTICE = 'notice';
    case WARNING = 'warning';
    case CRITICAL = 'critical';
}
