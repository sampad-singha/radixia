<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class ImmutableFieldException extends Exception
{
    public function __construct(
        $message = "One or more immutable fields were provided.",
        $code = 422
    )
    {
        parent::__construct($message, $code);
    }
}