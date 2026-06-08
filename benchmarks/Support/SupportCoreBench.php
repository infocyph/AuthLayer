<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Benchmarks\Support;

use Infocyph\AuthLayer\Support\ArrayTtlStore;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\RandomAuthIdGenerator;
use PhpBench\Attributes as Bench;

final class SupportCoreBench
{
    private RandomAuthIdGenerator $ids;

    private ArrayTtlStore $ttl;

    #[Bench\BeforeMethods('setUpTtlStore')]
    public function benchArrayTtlPutGetPull(): void
    {
        $this->ttl->put('auth:bench', ['account_id' => 'acct-1'], 300);
        $this->ttl->get('auth:bench');
        $this->ttl->pull('auth:bench');
    }

    #[Bench\BeforeMethods('setUpIds')]
    public function benchRandomSessionIdGeneration(): void
    {
        $this->ids->sessionId();
    }

    public function setUpIds(): void
    {
        $this->ids = new RandomAuthIdGenerator();
    }

    public function setUpTtlStore(): void
    {
        $this->ttl = new ArrayTtlStore(new FrozenClock(1000));
    }
}
