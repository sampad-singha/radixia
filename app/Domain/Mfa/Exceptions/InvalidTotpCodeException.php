<?php

namespace App\Domain\Mfa\Exceptions;

use Exception;

class InvalidTotpCodeException extends Exception
{
    public function __construct(string $message = "The provided two-factor authentication code is invalid.")
    {
        parent::__construct($message, 422); // 409 Conflict
    }
}
