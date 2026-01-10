<?php

namespace App\Domain\Mfa\Providers;

use App\Models\User;

interface MfaProviderInterface
{
    /**
     * Verify the provided code.
     */
    public function verify(User $user, string $code): bool;

    /**
     * Prepare challenge (e.g. send email).
     * Returns true if action was taken, false if passive (TOTP).
     */
    public function prepareChallenge(User $user): bool;

    /**
     * Generate setup data (QR code, secrets).
     */
    public function generateSetupData(User $user): array;

    /**
     * Finalize setup and persist to DB.
     */
    public function enable(User $user, string $secret, string $code): void;

    public function getType(): string;
}