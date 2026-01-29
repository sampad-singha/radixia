<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class RestrictedStatusException extends Exception
{
    public function __construct(string $status, $code = 422)
    {
        $message = "Cannot modify a cohort that is already {$status}.";
        parent::__construct($message, $code);
    }
}