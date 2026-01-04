<?php

namespace App\Domain\Auth\Services;

use App\Models\User;

interface EmailChangeServiceInterface
{
    /**
     * Initiate an email change request.
     */
    public function requestChange(User $user, string $newEmail): void;

    /**
     * Verify the token and commit the new email.
     */
    public function verifyChange(User $user, string $code): void;
}
