<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class EmailVerificationException extends Exception
{
    public function __construct()
    {
        parent::__construct('Invalid or expired verification link.', 400);
    }
}
