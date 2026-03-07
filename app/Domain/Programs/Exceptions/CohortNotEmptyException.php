<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class CohortNotEmptyException extends Exception
{
    public function __construct(int $count, $code = 422)
    {
        $message = "Cannot delete this cohort because it has {$count} active or pending enrollments.";
        parent::__construct($message, $code);
    }
}