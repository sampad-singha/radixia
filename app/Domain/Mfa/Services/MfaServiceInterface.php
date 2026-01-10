<?php

namespace App\Domain\Mfa\Services;

use App\Models\User;

interface MfaServiceInterface
{
    /**
     * Start the setup process for a specific MFA method.
     * Returns necessary setup data (e.g. QR code, secret) or empty array.
     */
    public function enable(User $user, string $type): array;

    /**
     * Confirm and activate the MFA method using a verification code.
     */
    public function confirm(User $user, string $type, string $code): void;

    /**
     * Disable a specific MFA method.
     */
    public function disable(User $user, string $type): void;

    /**
     * Regenerate recovery codes (TOTP only).
     */
    public function regenerateRecoveryCodes(User $user): array;

    /**
     * Get existing recovery codes.
     */
    public function getRecoveryCodes(User $user): array;

    /**
     * Check if MFA is required for the user based on provided data.
     * Returns an array with details if MFA is required, or null if not.
     */
    public function checkMfaRequirement(User $user, array $data): ?array;

    /**
     * Verify the provided MFA challenge code.
     * Throws exception if verification fails.
     */
    public function verifyMfaChallenge(User $user, string $code, string $type): void;
}
