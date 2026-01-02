<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class EmailAlreadyVerifiedException extends Exception
{
    public function __construct()
    {
        parent::__construct('Email is already verified.', 400);
    }
}
