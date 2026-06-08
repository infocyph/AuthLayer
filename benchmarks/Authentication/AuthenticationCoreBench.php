<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Benchmarks\Authentication;

use Infocyph\AuthLayer\Account\Account;
use Infocyph\AuthLayer\Account\AccountStatus;
use Infocyph\AuthLayer\Authentication\Lockout\LockoutConfig;
use Infocyph\AuthLayer\Authentication\Lockout\LockoutManager;
use Infocyph\AuthLayer\Authentication\Login\Authenticator;
use Infocyph\AuthLayer\Authentication\Login\LoginRequest;
use Infocyph\AuthLayer\Authentication\Session\SessionConfig;
use Infocyph\AuthLayer\Authentication\Session\SessionManager;
use Infocyph\AuthLayer\Contract\Security\PasswordVerificationResult;
use Infocyph\AuthLayer\Contract\Security\PasswordVerifierInterface;
use Infocyph\AuthLayer\Support\FrozenClock;
use Infocyph\AuthLayer\Support\InMemoryAccountStore;
use Infocyph\AuthLayer\Support\InMemoryAuditEventStore;
use Infocyph\AuthLayer\Support\InMemoryCounterStore;
use Infocyph\AuthLayer\Support\InMemoryLockoutStore;
use Infocyph\AuthLayer\Support\InMemorySessionStore;
use Infocyph\AuthLayer\Support\RandomAuthIdGenerator;
use PhpBench\Attributes as Bench;

final class AuthenticationCoreBench
{
    private Authenticator $authenticator;

    private SessionManager $sessions;

    #[Bench\BeforeMethods('setUpAuthenticator')]
    public function benchAuthenticatorLogin(): void
    {
        $this->authenticator->login(new LoginRequest(
            'alice@example.com',
            'secret',
            context: ['device_id' => 'dev-1', 'session_id' => 'sess-bench'],
        ));
    }

    #[Bench\BeforeMethods('setUpSessionManager')]
    public function benchSessionCreateAndRotate(): void
    {
        $session = $this->sessions->create('acct-1', 'dev-1', ['ip' => '127.0.0.1']);
        $this->sessions->rotate($session->id);
    }

    public function setUpAuthenticator(): void
    {
        $clock = new FrozenClock(1000);
        $ids = new RandomAuthIdGenerator();
        $accounts = new InMemoryAccountStore();
        $accounts->save(new Account('acct-1', 'alice@example.com', AccountStatus::ACTIVE, 'secret'));
        $audit = new InMemoryAuditEventStore();

        $this->authenticator = new Authenticator(
            $accounts,
            $accounts,
            new class implements PasswordVerifierInterface {
                public function verify(string $plainPassword, string $storedHash): PasswordVerificationResult
                {
                    return new PasswordVerificationResult($plainPassword === $storedHash);
                }
            },
            new SessionManager(new InMemorySessionStore(), $ids, new SessionConfig(3600, 900), $clock),
            $ids,
            $audit,
            new LockoutManager(
                new InMemoryCounterStore($clock),
                new InMemoryLockoutStore($clock),
                $audit,
                $ids,
                new LockoutConfig(10, 10, 10, 60, 120),
                $clock,
            ),
            $clock,
        );
    }

    public function setUpSessionManager(): void
    {
        $this->sessions = new SessionManager(
            new InMemorySessionStore(),
            new RandomAuthIdGenerator(),
            new SessionConfig(3600, 900),
            new FrozenClock(1000),
        );
    }
}
