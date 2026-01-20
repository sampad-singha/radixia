<?php

namespace App\Application\Mfa;

use App\Domain\Mfa\Factories\MfaFactoryInterface;
use App\Domain\Mfa\Providers\MfaProviderInterface;
use App\Infrastructure\Mfa\Providers\EmailMfaProvider;
use App\Infrastructure\Mfa\Providers\TotpMfaProvider;
use InvalidArgumentException;

readonly class MfaFactory implements MfaFactoryInterface
{
    public function __construct(
        private EmailMfaProvider $emailProvider,
        private TotpMfaProvider  $totpProvider
    ) {}

    public function make(string $type): MfaProviderInterface
    {
        return match ($type) {
            'email' => $this->emailProvider,
            'totp'  => $this->totpProvider,
            default => throw new InvalidArgumentException("Unsupported MFA type: {$type}"),
        };
    }
}
