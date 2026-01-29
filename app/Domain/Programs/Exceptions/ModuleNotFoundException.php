<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class ModuleNotFoundException extends Exception
{
    public function __construct()
    {
        parent::__construct('The requested module was not found.', 404);
    }
}