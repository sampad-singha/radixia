<?php

namespace App\Domain\Auth\Services;

interface SocialAuthServiceInterface
{
    /**
     * Handle the social login callback.
     *
     * @param string $provider (e.g., 'facebook')
     * @param string $frontendRedirectUrl
     * @return array Result containing 'status', 'token', 'user', or 'provider_user'
     */
    public function handleProviderCallback(string $provider, string $frontendRedirectUrl): array;
}