<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Audit;

enum AuthEventSeverity: string
{
    case CRITICAL = 'critical';

    case INFO = 'info';

    case NOTICE = 'notice';

    case WARNING = 'warning';
}
