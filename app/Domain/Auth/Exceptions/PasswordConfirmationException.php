<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class PasswordConfirmationException extends Exception
{
    public function __construct()
    {
        parent::__construct('The provided password does not match your current password.', 422);
    }
}
