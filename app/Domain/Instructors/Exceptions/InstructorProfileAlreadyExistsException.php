<?php

namespace App\Domain\Instructors\Exceptions;

use RuntimeException;

class InstructorProfileAlreadyExistsException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('User already has an instructor profile.', 409);
    }
}

