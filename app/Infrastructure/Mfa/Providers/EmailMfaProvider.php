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

        // Check if data exists
        if (! $method || empty($method->secret)) {
            return false;
        }

        // Access directly.
        // Model cast 'encrypted:array' has already decrypted and decoded this into an array.
        $data = $method->secret; // <--- CHANGED: No decrypt(), no json_decode()

        $targetHash = $data['hash'] ?? '';
        $expiresAtString = $data['expires_at'] ?? null;

        if (! $targetHash || ! $expiresAtString) {
            return false;
        }

        $expiresAt = Carbon::parse($expiresAtString);

        if ($expiresAt->isPast()) {
            return false;
        }

        if (Hash::check($code, $targetHash)) {
            // Clear secret (pass null)
            $method->update(['secret' => null]);
            return true;
        }

        return false;
    }

    public function enable(User $user, string $secret, string $code): void
    {
        $user->mfaMethods()->where('type', 'email')->update(['is_default' => true]);
    }
}
