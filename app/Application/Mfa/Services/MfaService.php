<?php

namespace App\Application\Mfa\Services;

use App\Application\Mfa\MfaFactory;
use App\Domain\Auth\Exceptions\InvalidTwoFactorCodeException;
use App\Domain\Mfa\Services\MfaServiceInterface;
use App\Models\User;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

class MfaService implements MfaServiceInterface
{
    public function __construct(
        private readonly MfaFactory $mfaFactory
    ) {}

    public function enable(User $user, string $type): array
    {
        $provider = $this->mfaFactory->make($type);

        // 1. Prepare Challenge (e.g. Send Email if type='email')
        $provider->prepareChallenge($user);

        // 2. Generate Setup Data (e.g. QR Code for TOTP)
        return $provider->generateSetupData($user);
    }

    /**
     * @throws InvalidTwoFactorCodeException
     */
    public function confirm(User $user, string $type, string $code): void
    {
        $provider = $this->mfaFactory->make($type);

        // Use the provider's logic to verify the code against the "pending" or passed secret.
        // For TOTP, we usually need the secret that was just generated.
        // Note: In stateless REST APIs, passing the secret back from the client is common
        // during confirmation, OR saving it to DB as 'pending' in enable().
        //
        // Assuming enable() saved it to DB as 'is_default=false' / 'pending'.
        // So we verify against the user's stored record.

        // We temporarily pass an empty string if the provider fetches secret from DB internally.
        if (! $provider->verify($user, $code)) {
            throw new InvalidTwoFactorCodeException();
        }

        // If successful, mark as confirmed/default
        // Note: You might need a specific method on Provider or direct DB update here.
        // We'll update directly for simplicity since we know the table structure.
        $user->mfaMethods()->where('type', $type)->update([
            'is_default' => true,
            // 'confirmed_at' => now(), // If you have this column
        ]);
    }

    public function disable(User $user, string $type): void
    {
        // Delete the method record
        $user->mfaMethods()->where('type', $type)->delete();

        // Optional: If no methods left, ensure no MFA flag is set on User?
        // (Not needed if you check mfaMethods()->exists() in AuthService)
    }

    public function regenerateRecoveryCodes(User $user): array
    {
        // Recovery codes are specific to TOTP in this architecture
        $method = $user->mfaMethods()->where('type', 'totp')->first();

        if (! $method) {
            // Or throw specific exception
            return [];
        }

        // Generate 8 pairs of 10-char codes
        $codes = Collection::times(8, fn () => Str::random(10) . '-' . Str::random(10))->all();

        $method->update([
            'backup_codes' => encrypt(json_encode($codes))
        ]);

        return $codes;
    }

    public function getRecoveryCodes(User $user): array
    {
        $method = $user->mfaMethods()->where('type', 'totp')->first();

        if ($method && $method->backup_codes) {
            return json_decode(decrypt($method->backup_codes), true);
        }

        return [];
    }
}