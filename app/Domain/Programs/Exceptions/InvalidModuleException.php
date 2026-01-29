<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class InvalidModuleException extends Exception
{
    public function __construct($message = 'The module is invalid.')
    {
        parent::__construct($message, 404);
    }
}