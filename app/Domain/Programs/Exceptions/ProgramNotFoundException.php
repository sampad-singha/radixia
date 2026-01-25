<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class ProgramNotFoundException extends Exception
{
    public function __construct()
    {
        parent::__construct('The requested program was not found.', 404);
    }
}