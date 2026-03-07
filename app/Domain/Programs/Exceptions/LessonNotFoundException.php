<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class LessonNotFoundException extends Exception
{
    public function __construct($message = 'The requested lesson was not found.')
    {
        parent::__construct($message, 404);
    }
}