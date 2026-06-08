<?php

declare(strict_types=1);

use Infocyph\AuthLayer\Device\DeviceManager;
use Infocyph\AuthLayer\Device\DeviceStatus;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\InMemoryDeviceStore;
use Infocyph\AuthLayer\Tests\Fixtures\TestAuthIdGenerator;

it('registers, trusts, touches, lists, and revokes devices', function (): void {
    $clock = new FrozenClock(1000);
    $store = new InMemoryDeviceStore($clock);
    $manager = new DeviceManager($store, new TestAuthIdGenerator(), $clock);

    $registered = $manager->register('acct-1', 'Laptop', 'fp-1', ['os' => 'linux']);
    $deviceId = $registered->device?->id ?? '';
    $trusted = $manager->trust($deviceId);
    $touched = $manager->touch($deviceId, 1010);
    $listed = $manager->listForAccount('acct-1');
    $revoked = $manager->revoke($deviceId);
    $missing = $manager->touch('missing');

    expect($registered->status)->toBe(DeviceStatus::REGISTERED)
        ->and($trusted->device?->trusted)->toBeTrue()
        ->and($touched->device?->lastSeenAt)->toBe(1010)
        ->and($listed)->toHaveCount(1)
        ->and($revoked->status)->toBe(DeviceStatus::REVOKED)
        ->and($store->find($deviceId)?->isRevoked())->toBeTrue()
        ->and($missing->status)->toBe(DeviceStatus::NOT_FOUND);
});

it('returns not-found results for unknown devices', function (): void {
    $clock = new FrozenClock(1000);
    $manager = new DeviceManager(new InMemoryDeviceStore($clock), new TestAuthIdGenerator(), $clock);

    expect($manager->trust('missing')->status)->toBe(DeviceStatus::NOT_FOUND)
        ->and($manager->touch('missing')->status)->toBe(DeviceStatus::NOT_FOUND)
        ->and($manager->revoke('missing')->status)->toBe(DeviceStatus::NOT_FOUND);
});
