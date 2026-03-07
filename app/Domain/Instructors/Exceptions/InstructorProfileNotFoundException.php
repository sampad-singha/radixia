<?php

namespace App\Domain\Instructors\Exceptions;

use RuntimeException;

class InstructorProfileNotFoundException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('Instructor profile not found.', 404);
    }
}
