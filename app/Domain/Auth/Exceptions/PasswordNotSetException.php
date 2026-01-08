<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class PasswordNotSetException extends Exception
{
    public function __construct(string $message = "User has no password set.")
    {
        parent::__construct($message, 400);
    }
}
