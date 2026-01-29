<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class CohortNotFoundException extends Exception
{
    public function __construct($message = 'The requested cohort was not found.')
    {
        parent::__construct($message, 404);
    }
}