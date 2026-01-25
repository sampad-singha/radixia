<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class ProgramNotFoundException extends Exception
{
    public function __construct($message = 'The requested program was not found.')
    {
        parent::__construct($message, 404);
    }
}