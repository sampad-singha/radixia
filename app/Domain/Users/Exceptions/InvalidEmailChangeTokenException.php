<?php

namespace App\Domain\Users\Exceptions;

use RuntimeException;

class InvalidEmailChangeTokenException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('The email verification code is invalid or expired.');
    }
}