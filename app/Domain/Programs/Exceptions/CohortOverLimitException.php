<?php

namespace App\Domain\Programs\Exceptions;

use RuntimeException;

class CohortOverLimitException extends RuntimeException
{
    public function __construct($message = 'This cohort is full. Please try again later if a reservation expires.')
    {
        parent::__construct($message, 409);
    }
}