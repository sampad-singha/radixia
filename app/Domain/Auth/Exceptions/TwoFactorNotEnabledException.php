<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class TwoFactorNotEnabledException extends Exception
{
    public function __construct()
    {
        parent::__construct('Two-factor authentication is not enabled.');
    }
}
