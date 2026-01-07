<?php

namespace App\Infrastructure\Mfa\Providers;

use App\Domain\Mfa\Providers\MfaProviderInterface;
use App\Models\User;
use Exception;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Laravel\Fortify\TwoFactorAuthenticationProvider;

readonly class TotpMfaProvider implements MfaProviderInterface
{

    public function __construct(
        private TwoFactorAuthenticationProvider $provider
    ) {}

    public function verify(User $user, string $code): bool
    {
        $method = $user->mfaMethods()->where('type', 'totp')->first();

        if (! $method || ! $method->secret) {
            return false;
        }

        // 1. Check Recovery Codes (The Bypass)
        // We assume the input might be a recovery code.
        // Recovery codes usually have a specific format (e.g., 10 chars), but we can just check the array.
        if ($method->backup_codes) {
//            $backupCodes = json_decode(decrypt($method->backup_codes), true);
            $backupCodes = $method->backup_codes;

            // Search for the code in the array
            $index = array_search($code, $backupCodes);

            if ($index !== false) {
                // Code Found! Remove it.
                unset($backupCodes[$index]);

                // Update DB with remaining codes
                $method->update(['backup_codes' => array_values($backupCodes)]);

                return true;
            }
        }

        // 2. Standard TOTP Verification
        // If it wasn't a backup code, try the Time-Based code.
        return $this->provider->verify($method->secret, $code);
    }

    public function prepareChallenge(User $user): bool
    {
        return false; // Passive
    }

    public function generateSetupData(User $user): array
    {
        $secret = $this->provider->generateSecretKey();
        $recoveryCodes = Collection::times(8, fn () => Str::random(10) . '-' . Str::random(10))->all();

        $user->mfaMethods()->updateOrCreate(
            ['type' => 'totp'],
            [
                'secret' => $secret, // Model handles encryption
                'backup_codes' => $recoveryCodes, // Model handles JSON+Encryption
                // Keep is_default as whatever it was, or false if new.
                // If we force false, we might disable an active method if they are just regenerating?
                // For "Enable" flow, usually we assume they are setting it up.
                'is_default' => false
            ]
        );

        return [
            'secret' => $secret,
            'qr_code_url' => $this->provider->qrCodeUrl(config('app.name'), $user->email, $secret),
            'recovery_codes' => $recoveryCodes
        ];
    }

    public function enable(User $user, string $secret, string $code): void
    {
        if (! $this->provider->verify($secret, $code)) {
            throw new Exception("Invalid TOTP Code");
        }

        // Generate fresh codes on enable
        $recoveryCodes = Collection::times(8, fn () => Str::random(10) . '-' . Str::random(10))->all();

        $user->mfaMethods()->updateOrCreate(
            ['type' => 'totp'],
            [
                'secret' => $secret,
                'backup_codes' => $recoveryCodes,
                'is_default' => true
            ]
        );
    }

    public function getType(): string
    {
        return 'totp';
    }
}
