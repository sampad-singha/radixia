<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class CohortUpdateException extends Exception
{
    public function __construct($message = 'Cannot update this cohort.')
    {
        parent::__construct($message, 422);
    }
}