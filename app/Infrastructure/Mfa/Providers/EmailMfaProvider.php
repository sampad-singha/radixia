<?php

namespace App\Infrastructure\Mfa\Providers;

use App\Domain\Mfa\Providers\MfaProviderInterface;
use App\Models\User;
use App\Notifications\VerifyTwoFactorAuthentication;
use Carbon\Carbon;
use Illuminate\Support\Facades\Hash;
use Random\RandomException;

class EmailMfaProvider implements MfaProviderInterface
{
    public function getType(): string
    {
        return 'email';
    }

    /**
     * @throws RandomException
     */
    public function generateSetupData(User $user): array
    {
        // Setup for email is just triggering the first challenge
        $this->prepareChallenge($user);
        return ['message' => 'Verification code sent to your email.'];
    }

    /**
     * @throws RandomException
     */
    public function prepareChallenge(User $user): bool
    {
        $code = (string) random_int(100000, 999999);

        // Define payload as a regular ARRAY
        $payload = [
            'hash' => Hash::make($code),
            'expires_at' => now()->addMinutes(10)->toIso8601String(),
        ];

        // Save ARRAY directly.
        // Model cast 'encrypted:array' will handle json_encode + encrypt automatically.
        $user->mfaMethods()->updateOrCreate(
            ['type' => 'email'],
            [
                'secret' => $payload, // <--- CHANGED: No encrypt(), no json_encode()
                'is_default' => false
            ]
        );

        $user->notify(new VerifyTwoFactorAuthentication($code));

        return true;
    }

    public function verify(User $user, string $code): bool
    {
        $method = $user->mfaMethods()->where('type', 'email')->first();

        // 1. Fail early if basic data is missing
        if (! $method || empty($method->secret)) {
            return false;
        }

        $data = $method->secret;
        $targetHash = $data['hash'] ?? '';
        $expiresAtString = $data['expires_at'] ?? null;

        // 2. Fail early if payload is invalid
        if (! $targetHash || ! $expiresAtString) {
            return false;
        }

        // 3. Perform final validation
        $expiresAt = Carbon::parse($expiresAtString);
        $isValid = ! $expiresAt->isPast() && Hash::check($code, $targetHash);

        if ($isValid) {
            $method->update(['secret' => null]);
        }

        return $isValid;
    }

    public function enable(User $user, string $secret, string $code): void
    {
        $user->mfaMethods()->where('type', 'email')->update(['is_default' => true]);
    }
}
