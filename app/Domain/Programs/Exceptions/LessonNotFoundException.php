<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class LessonNotFoundException extends Exception
{
    public function __construct()
    {
        parent::__construct('The requested lesson was not found.', 404);
    }
}