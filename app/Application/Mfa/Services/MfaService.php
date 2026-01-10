<?php

namespace App\Application\Mfa\Services;

use App\Application\Mfa\MfaFactory;
use App\Domain\Auth\Exceptions\InvalidTwoFactorCodeException;
use App\Domain\Mfa\Services\MfaServiceInterface;
use App\Models\User;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

readonly class MfaService implements MfaServiceInterface
{
    public function __construct(
        private MfaFactory $mfaFactory
    ) {}

    public function enable(User $user, string $type): array
    {
        $provider = $this->mfaFactory->make($type);

        // 2. Generate Setup Data (e.g. QR Code for TOTP)
        return $provider->generateSetupData($user);
    }

    /**
     * @throws InvalidTwoFactorCodeException
     */
    public function confirm(User $user, string $type, string $code): void
    {
        $provider = $this->mfaFactory->make($type);

        if (! $provider->verify($user, $code)) {
            throw new InvalidTwoFactorCodeException();
        }

        $user->mfaMethods()->where('type', $type)->update([
            'is_default' => true,
        ]);
    }

    public function disable(User $user, ?string $type = null): void
    {
        $query = $user->mfaMethods();

        if ($type) {
            // Disable specific method
            $query->where('type', $type);
        }

        // If $type is null, this deletes ALL rows (Global Disable)
        $query->delete();
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
            'backup_codes' => $codes
        ]);

        return $codes;
    }

    public function getRecoveryCodes(User $user): array
    {
        $method = $user->mfaMethods()->where('type', 'totp')->first();

        if ($method && $method->backup_codes) {
            return $method->backup_codes;
        }

        return [];
    }

    /**
     * @throws InvalidTwoFactorCodeException
     */
    public function checkMfaRequirement(User $user, array $data): ?array
    {
        $user->load('mfaMethods');
        $enabledMethods = $user->mfaMethods->pluck('type')->toArray();

        if (empty($enabledMethods)) {
            return null; // Proceed
        }

        // Validate requested type against enabled methods
        // If the user requests a type they haven't enabled, ignore the input.
        $requestedType = isset($data['mfa_type']) && in_array($data['mfa_type'], $enabledMethods)
            ? $data['mfa_type']
            : null;

        // Fallback logic:
        // 1. Use the validated requested type.
        // 2. Or use the user's default method (using the loaded collection to avoid DB query).
        // 3. Or use the first available enabled method.
        $requestedType = $requestedType
            ?? $user->mfaMethods->firstWhere('is_default', true)?->type
            ?? $enabledMethods[0];

        // B. CHALLENGE PHASE (No Code)
        $provider = $this->mfaFactory->make($requestedType);

        $challengeSent = $provider->prepareChallenge($user);

        return [
            'mfa_required' => true,
            'available_methods' => $enabledMethods,
            'challenge_sent' => $challengeSent,
            'message' => $challengeSent
                ? "Challenge sent via {$requestedType}."
                : "Two-factor authentication required."
        ];
    }

    /**
     * @throws InvalidTwoFactorCodeException
     */
    public function verifyMfaChallenge(User $user, string $code, string $type): void
    {
        // Ensure method is actually enabled
        $method = $user->mfaMethods()->where('type', $type)->first();

        if (! $method) {
            throw new InvalidTwoFactorCodeException("Method not enabled.");
        }

        $provider = $this->mfaFactory->make($type);

        if (! $provider->verify($user, $code)) {
            throw new InvalidTwoFactorCodeException();
        }

        // Update usage timestamp
        $method->update(['last_used_at' => now()]);
    }
}
