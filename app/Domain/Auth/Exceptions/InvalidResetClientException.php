<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class InvalidResetClientException extends Exception
{
    public function __construct(string $message = 'Invalid reset client')
    {
        parent::__construct($message);
    }
}
