<?php

namespace App\Application\Auth\Services;

use App\Domain\Users\Exceptions\InvalidEmailChangeTokenException;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Domain\Users\Services\EmailChangeServiceInterface;
use App\Models\User;
use App\Notifications\VerifyChangeEmail;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use Random\RandomException;

class EmailChangeService implements EmailChangeServiceInterface
{
    public function __construct(
        private readonly UserRepositoryInterface $users
    ) {}

    /**
     * @throws RandomException
     */
    public function requestChange(User $user, string $newEmail): void
    {
        // 1. Generate a random 6-digit code or secure token
        $token = (string) random_int(100000, 999999);

        // 2. Persist to DB
        $this->users->setPendingEmail($user, $newEmail, $token);

        // 3. Send notification to the NEW email
        Notification::route('mail', $newEmail)
            ->notify(new VerifyChangeEmail($token));
    }

    public function verifyChange(User $user, string $code): void
    {
        $dummyHash = '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi';
        $targetHash = $user->pending_email_token ?? $dummyHash;
        $isValidToken = Hash::check($code, $targetHash);
        // 1. Validate Token
        if (
            ! $user->pending_email ||
            ! $user->pending_email_token ||
            ! $isValidToken
        ) {
            throw new InvalidEmailChangeTokenException();
        }

        // 2. Update actual Email and clear pending
        $this->users->setEmail($user, $user->pending_email);
        $this->users->clearPendingEmail($user); // Clear pending columns
    }
}