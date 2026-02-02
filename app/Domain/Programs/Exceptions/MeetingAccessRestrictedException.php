<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class MeetingAccessRestrictedException extends Exception
{
    public function __construct(string $message = "Cannot Join this meeting.", $code = 403)
    {
        parent::__construct($message, $code);
    }
}