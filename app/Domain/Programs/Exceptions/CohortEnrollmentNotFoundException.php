<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class CohortEnrollmentNotFoundException extends Exception
{
    public function __construct($message = 'Enrollment record missing.')
    {
        parent::__construct($message, 404);
    }
}