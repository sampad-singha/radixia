<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class TwoFactorNotConfirmedException extends Exception
{
    public function __construct()
    {
        parent::__construct('Two-factor authentication is not confirmed.');
    }
}
