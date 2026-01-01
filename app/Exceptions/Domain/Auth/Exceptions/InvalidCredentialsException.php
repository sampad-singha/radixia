<?php

namespace App\Exceptions\Domain\Auth\Exceptions;

use Exception;
use RuntimeException;

class InvalidCredentialsException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('The provided credentials are incorrect.', 401);
    }
}
