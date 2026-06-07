<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Device;

use Infocyph\AuthLayer\Support\HasEnumStatusResult;

final readonly class DeviceResult
{
    use HasEnumStatusResult;

    /**
     * @param list<DeviceRecord> $devices
     * @param array<string, mixed> $context
     */
    public function __construct(
        public DeviceStatus $status,
        public ?DeviceRecord $device = null,
        public array $devices = [],
        public ?string $code = null,
        public array $context = [],
    ) {}

    /**
     * @return list<object>
     */
    protected function successStatuses(): array
    {
        return [
            DeviceStatus::REGISTERED,
            DeviceStatus::TRUSTED,
            DeviceStatus::TOUCHED,
            DeviceStatus::REVOKED,
        ];
    }
}
