<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class ActiveCohortsException extends Exception
{
    public function __construct(
        $message = "Cannot archive a program that still has scheduled or active cohorts.",
        $code = 422
    )
    {
        parent::__construct($message, $code);
    }
}