<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Device;

final readonly class DeviceResult
{
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
    ) {
    }
}
