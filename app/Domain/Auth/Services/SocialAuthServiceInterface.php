<?php

namespace App\Domain\Auth\Services;

interface SocialAuthServiceInterface
{
    /**
     * Handle the social login callback.
     *
     * @param string $provider (e.g., 'facebook')
     * @param string $code (OAuth code from frontend)
     * @param string|null $manualEmail (Optional email provided by user if missing)
     * @return array Result containing 'status', 'token', 'user', or 'provider_user'
     */
    public function handleProviderCallback(string $provider, string $code, string $frontendRedirectUrl, ?string $manualEmail = null): array;
}