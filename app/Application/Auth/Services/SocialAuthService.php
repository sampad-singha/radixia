<?php

namespace App\Application\Auth\Services;

use App\Application\Mfa\Services\MfaService;
use App\Domain\Auth\Exceptions\InvalidTwoFactorCodeException;
use App\Domain\Auth\Exceptions\SocialProviderException;
use App\Domain\Auth\Exceptions\SocialEmailRequiredException;
use App\Domain\Auth\Repositories\AccessTokenRepositoryInterface;
use App\Domain\Auth\Repositories\SocialAccountRepositoryInterface;
use App\Domain\Auth\Services\SocialAuthServiceInterface;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Models\User;
use Exception;
use GuzzleHttp\Exception\ClientException;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteUser;
use Log;

readonly class SocialAuthService implements SocialAuthServiceInterface
{
    public function __construct(
        private UserRepositoryInterface          $users,
        private SocialAccountRepositoryInterface $socialAccounts,
        private AccessTokenRepositoryInterface   $tokens,
        private MfaService                       $mfaService,
    )
    {
    }


    /**
     * @throws SocialEmailRequiredException
     * @throws SocialProviderException
     * @throws InvalidTwoFactorCodeException
     */
    public function handleProviderCallback(string $provider, string $code, string $frontendRedirectUrl, ?string $manualEmail = null): array
    {
        /*The code is not directly used here because Socialite handles the exchange internally.
        But we kept it to make it clear which parameter is expected.*/
        try {
            /** @var SocialiteUser $providerUser */
            $providerUser = Socialite::driver($provider)
                ->redirectUrl($frontendRedirectUrl)
                ->stateless()
                ->user();
        } catch (ClientException $e) {
            $statusCode = $e->getResponse()->getStatusCode();
            $body = json_decode($e->getResponse()->getBody()->getContents(), true);

            // Log deep details for dev
            Log::error("Social Auth Provider Error [{$statusCode}]: " . json_encode($body));

            // CASE A: Server Side Config Error (401 Unauthorized, 403 Forbidden)
            if ($statusCode === 401 || $statusCode === 403) {
                throw new SocialProviderException(
                    "Social authentication service is unavailable.",
                    'SOCIAL_CONFIG_ERROR',
                    500
                );
            }

            // CASE B: Client Side Input Error (400 Bad Request)
            // (invalid_grant, redirect_uri_mismatch, etc.)
            throw new SocialProviderException(
                "Social login failed. The session may have expired.",
                'SOCIAL_LOGIN_FAILED',
                400
            );

        } catch (Exception $e) {
            Log::error("Social Auth General Error: " . $e->getMessage());

            throw new SocialProviderException(
                "An unexpected error occurred during login.",
                'INTERNAL_ERROR',
                500
            );
        }

        // 1. Check Linked Account
        $account = $this->socialAccounts->findByProvider($provider, $providerUser->getId());

        if ($account) {
            $this->socialAccounts->updateTokens(
                $account,
                $providerUser->token,
                $providerUser->refreshToken,
                $providerUser->expiresIn
            );
            return $this->issueToken($account->user);
        }

        // 2. Validate Email
        $email = $providerUser->getEmail() ?? $manualEmail;

        if (!$email) {
            throw new SocialEmailRequiredException([
                'id' => $providerUser->getId(),
                'name' => $providerUser->getName(),
                'avatar' => $providerUser->getAvatar(),
            ]);
        }

        // 3. Register or Link
        $user = $this->users->findByEmail($email);

        if (!$user) {
            $userData = [
                'name' => $providerUser->getName() ?? 'User',
                'email' => $email,
                'password' => Hash::make(Str::random(32)),
                'email_verified_at' => now(),
            ];

            $user = $this->socialAccounts->registerUserWithSocial($userData, $provider, $providerUser);
        } else {
            $this->socialAccounts->create(
                $user,
                $provider,
                $providerUser->getId(),
                $providerUser->token,
                $providerUser->refreshToken,
                $providerUser->expiresIn,
                $providerUser->getAvatar()
            );
        }

        return $this->issueToken($user);
    }

    /**
     * @throws InvalidTwoFactorCodeException
     */
    private function issueToken(User $user): array
    {
        // 1. Check MFA
        $mfaResult = $this->mfaService->checkMfaRequirement($user, request()->all());

        if ($mfaResult) {
            // Create Temp Token for Social Flow
            $tempToken = $this->tokens->create(
                $user,
                'social-mfa-pending',
                request()->ip(),
                request()->userAgent(),
                ['mfa:verify']);
            $mfaResult['token'] = $tempToken;
            return $mfaResult;
        }

        // 2. Standard Login
        $token = $this->tokens->create($user, 'social-login', request()->ip(), request()->userAgent());
        return ['status' => 'SUCCESS', 'token' => $token, 'user' => $user];
    }
}
