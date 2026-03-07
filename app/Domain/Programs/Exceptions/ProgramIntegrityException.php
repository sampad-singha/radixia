<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class ProgramIntegrityException extends Exception
{
    public function __construct($message = 'Lesson or module does not belong to the Program associated with this Cohort.')
    {
        parent::__construct($message, 404);
    }
}