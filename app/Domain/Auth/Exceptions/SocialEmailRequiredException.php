<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class SocialEmailRequiredException extends Exception
{
    public function __construct(public array $providerUser)
    {
        parent::__construct('Email address is required to complete registration.');
    }
}
