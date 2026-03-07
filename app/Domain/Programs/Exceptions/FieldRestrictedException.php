<?php

namespace App\Domain\Programs\Exceptions;

use Exception;

class FieldRestrictedException extends Exception
{
    public function __construct(string $field, $code = 422)
    {
        $message = "Cannot change {$field} because students are already enrolled.";
        parent::__construct($message, $code);
    }
}