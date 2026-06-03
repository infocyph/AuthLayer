<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\StepUp;

final readonly class StepUpRequirement
{
    public function __construct(
        public string $ability,
        public int $maxAgeSeconds = 900,
        public StepUpMethod $method = StepUpMethod::RECENT_AUTH,
    ) {
    }
}
