<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class SessionOutsideCohortRangeException extends Exception
{
    public function __construct(
        $message = "Session must be within cohort date range",
        $code = 422
    )
    {
        parent::__construct($message, $code);
    }
}