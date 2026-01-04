<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class PasswordResetException extends Exception
{
    protected string $brokerStatus;

    public function __construct(string $brokerStatus)
    {
        $this->brokerStatus = $brokerStatus;

        parent::__construct(__($brokerStatus));
    }

    public function brokerStatus(): string
    {
        return $this->brokerStatus;
    }
}
