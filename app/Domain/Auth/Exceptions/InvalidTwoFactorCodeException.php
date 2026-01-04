<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class InvalidTwoFactorCodeException extends Exception
{
    public function __construct()
    {
        parent::__construct('The provided two-factor authentication code is invalid.');
    }
}
