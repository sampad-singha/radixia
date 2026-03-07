<?php

namespace App\Domain\Auth\Exceptions;

use Exception;

class SocialProviderException extends Exception
{
    public string $errorCode;

    public function __construct(string $message = 'Social Login Failed', string $errorCode = 'SOCIAL_LOGIN_FAILED', int $httpStatus = 500)
    {
        parent::__construct($message, $httpStatus);
        $this->errorCode = strtoupper($errorCode);
    }
}
