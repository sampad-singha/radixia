<?php

namespace App\Domain\Mfa\Factories;

use App\Domain\Mfa\Providers\MfaProviderInterface;

interface MfaFactoryInterface
{
    public function make(string $type): MfaProviderInterface;
}
