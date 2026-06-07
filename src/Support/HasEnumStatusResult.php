<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

trait HasEnumStatusResult
{
    /**
     * @return list<object>
     */
    abstract protected function successStatuses(): array;

    public function failed(): bool
    {
        return !$this->successful();
    }

    public function successful(): bool
    {
        return in_array($this->status, $this->successStatuses(), true);
    }
}
