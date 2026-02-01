<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class InvalidSessionTimeException extends Exception
{
    public function __construct(
        $message = "Invalid Session Time provided.",
        $code = 422
    )
    {
        parent::__construct($message, $code);
    }
}