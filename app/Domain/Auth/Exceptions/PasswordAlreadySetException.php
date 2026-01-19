<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class PasswordAlreadySetException extends Exception
{
    public function __construct(string $message = "User already has a password set.")
    {
        parent::__construct($message, 409); // 409 Conflict
    }
}
