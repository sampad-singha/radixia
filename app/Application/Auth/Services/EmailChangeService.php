<?php

namespace App\Application\Auth\Services;

use App\Domain\Auth\Services\EmailChangeServiceInterface;
use App\Domain\Users\Exceptions\InvalidEmailChangeTokenException;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Models\User;
use App\Notifications\VerifyChangeEmail;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Random\RandomException;

readonly class EmailChangeService implements EmailChangeServiceInterface
{
    public function __construct(
        private UserRepositoryInterface $users
    ) {}

    /**
     * @throws RandomException
     */
    public function requestChange(User $user, string $newEmail): void
    {
        // 1. Generate a random 6-digit code or secure token
        $token = (string) random_int(100000, 999999);

        // 2. Persist to DB
        $timeoutMinutes = config('auth.email_change_timeout', 60);

        $this->users->setPendingEmail(
            $user,
            $newEmail,
            Hash::make($token),
            now()->addMinutes($timeoutMinutes)
        );

        // 3. Send notification to the NEW email
        Notification::route('mail', $newEmail)
            ->notify(new VerifyChangeEmail($token, $timeoutMinutes));
    }

    public function verifyChange(User $user, string $code): void
    {
        $dummyHash = Hash::make('dummy_secret');
        $targetHash = $user->pending_email_token ?? $dummyHash;
        $isValidToken = Hash::check($code, $targetHash);
        $isExpired = $user->pending_email_expires_at && $user->pending_email_expires_at->isPast();
        // 1. Validate Token
        if (
            ! $user->pending_email ||
            ! $user->pending_email_token ||
            ! $isValidToken ||
            $isExpired
        ) {
            throw new InvalidEmailChangeTokenException();
        }

        // 2. Update actual Email and clear pending
        $this->users->setEmail($user, $user->pending_email);
        $this->users->clearPendingEmail($user); // Clear pending columns
    }
}
