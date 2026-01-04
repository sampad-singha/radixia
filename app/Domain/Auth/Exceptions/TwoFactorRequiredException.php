<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class TwoFactorRequiredException extends Exception
{
    public function __construct()
    {
        parent::__construct('Two-factor authentication code required.');
    }
}
