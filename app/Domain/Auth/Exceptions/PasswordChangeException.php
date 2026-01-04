<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class PasswordChangeException extends Exception
{
    public function __construct(string $message = 'Failed to change password.')
    {
        parent::__construct($message);
    }
}
