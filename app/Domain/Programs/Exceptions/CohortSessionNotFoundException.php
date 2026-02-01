<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class CohortSessionNotFoundException extends Exception
{
    public function __construct(
        $message = "Cohort session not found.",
        $code = 404
    )
    {
        parent::__construct($message, $code);
    }
}