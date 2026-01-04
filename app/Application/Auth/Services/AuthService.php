<?php

namespace App\Application\Auth\Services;

use App\Domain\Auth\Exceptions\EmailAlreadyVerifiedException;
use App\Domain\Auth\Exceptions\EmailVerificationException;
use App\Domain\Auth\Exceptions\InvalidCredentialsException;
use App\Domain\Auth\Exceptions\InvalidResetClientException;
use App\Domain\Auth\Exceptions\InvalidTwoFactorCodeException;
use App\Domain\Auth\Exceptions\PasswordConfirmationException;
use App\Domain\Auth\Exceptions\PasswordResetException;
use App\Domain\Auth\Exceptions\PasswordResetLinkException;
use App\Domain\Auth\Exceptions\TwoFactorNotConfirmedException;
use App\Domain\Auth\Exceptions\TwoFactorNotEnabledException;
use App\Domain\Auth\Repositories\AccessTokenRepositoryInterface;
use App\Domain\Auth\Repositories\TwoFactorRepositoryInterface;
use App\Domain\Auth\Services\AuthServiceInterface;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Models\User;
use App\Notifications\ResetPasswordNotification;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Contracts\Auth\PasswordBroker;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Laravel\Fortify\Contracts\CreatesNewUsers;
use Laravel\Fortify\Contracts\ResetsUserPasswords;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;
use Laravel\Fortify\RecoveryCode;

class AuthService implements AuthServiceInterface
{
    public function __construct(
        private readonly UserRepositoryInterface $users,
        private readonly AccessTokenRepositoryInterface $tokens,
        private readonly TwoFactorRepositoryInterface $twoFactor,
        private readonly CreatesNewUsers $createsNewUsers,
        private readonly ResetsUserPasswords $resetsUserPasswords,
        private readonly PasswordBroker $passwordBroker,
        private readonly TwoFactorAuthenticationProvider $twoFactorProvider,
    ) {}

    public function register(array $data, ?string $ip, ?string $userAgent): array
    {
        $user = $this->createsNewUsers->create($data);

        event(new Registered($user));

        $token = $this->tokens->create(
            $user,
            $data['device_name'],
            $ip,
            $userAgent
        );

        return ['user' => $user, 'token' => $token];
    }

    /**
     * @throws EmailVerificationException
     */
    public function verifyEmail(int $id, string $hash): bool
    {
        $user = $this->users->findById($id);

        $emailForVerification = $user ? $user->getEmailForVerification() : 'email_verification_dummy_value';
        $expectedHash = sha1($emailForVerification);

        if (! $user || ! hash_equals($expectedHash, (string) $hash)) {
            throw new EmailVerificationException();
        }

        if ($user->hasVerifiedEmail()) {
            return true;
        }

        // use repository to persist email verification
        $this->users->markEmailVerified($user);

        event(new Verified($user));

        return true;
    }

    /**
     * @throws EmailAlreadyVerifiedException
     */
    public function resendVerificationNotification(User $user): void
    {
        if ($user->hasVerifiedEmail()) {
            throw new EmailAlreadyVerifiedException();
        }

        $user->sendEmailVerificationNotification();
    }

    /**
     * @throws InvalidCredentialsException|InvalidTwoFactorCodeException
     */
    public function login(array $data, ?string $ip, ?string $userAgent): array
    {
        $user = $this->users->findByEmail($data['email']);

        if (! $user || ! Hash::check($data['password'], $user->password)) {
            throw new InvalidCredentialsException();
        }

        // 2FA requirement / verification
        if ($user->hasEnabledTwoFactorAuthentication()) {
            if (empty($data['two_factor_code']) && empty($data['recovery_code'])) {
                return [
                    'two_factor_required' => true,
                    'message' => 'Two-factor authentication required.',
                ];
            }

            $this->verifyTwoFactorCode($user, $data);
        }

        // Use AccessTokenRepository to create token and persist metadata
        $token = $this->tokens->create($user, $data['device_name'], $ip, $userAgent);

        return ['user' => $user, 'token' => $token];
    }

    public function logout(User $user): void
    {
        $currentToken = $this->tokens->current($user);

        if ($currentToken) {
            $this->tokens->revoke($user, (string) $currentToken->id);
        }
    }

    /**
     * @throws InvalidResetClientException
     */
    public function forgotPassword(array $data, string $client): string
    {
        $resetUrlBase = config("auth.reset_clients.$client");

        if (! $resetUrlBase) {
            throw new InvalidResetClientException("Invalid client: $client");
        }

        // 1. Get the user
        $user = $this->users->findByEmail($data['email']);

        if (! $user) {
            // Return success to prevent email enumeration, or throw based on your policy
            return Password::RESET_LINK_SENT;
        }

        // 2. Generate Token Manually
        $token = Password::broker()->createToken($user);

        // 3. Build the specific URL for this request
        $url = $resetUrlBase . '?token=' . $token . '&email=' . urlencode($user->email);

        // 4. Send Notification explicitly
        $user->notify(new ResetPasswordNotification($url));

        return Password::RESET_LINK_SENT;
    }

    /**
     * @throws PasswordResetException
     */
    public function resetPassword(array $data): string
    {
        $status = $this->passwordBroker->reset(
            $data,
            function ($user, $password) {
                $this->resetsUserPasswords->reset($user, [
                    'password' => $password,
                    'password_confirmation' => $password,
                ]);

                $this->tokens->revokeAll($user);
            }
        );

        if ($status !== Password::PASSWORD_RESET) {
            throw new PasswordResetException($status);
        }

        return __($status);
    }

    /**
     * @throws PasswordConfirmationException
     */
    public function confirmPassword(User $user, string $password): bool
    {
        if (! Hash::check($password, $user->password)) {
            throw new PasswordConfirmationException();
        }

        $token = $this->tokens->current($user);

        if ($token) {
            $this->tokens->setSudoExpiration($token, config('auth.password_timeout', 600));
        }

        return true;
    }

    public function passwordConfirmedStatus(User $user): bool
    {
        return $this->tokens->isSudoActive($user);
    }

    public function enableTwoFactor(User $user): array
    {
        $secretKey = $this->twoFactorProvider->generateSecretKey();

        $recoveryCodes = Collection::times(8, fn () => RecoveryCode::generate())->all();

        $this->twoFactor->enable($user, $secretKey, $recoveryCodes);

        $appName = config('app.name');
        $otpAuthUrl = sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s',
            rawurlencode($appName),
            rawurlencode($user->email),
            $secretKey,
            rawurlencode($appName)
        );

        return [
            'two_factor_url' => $otpAuthUrl,
            'secret' => $secretKey,
            'recovery_codes' => $recoveryCodes,
        ];
    }

    /**
     * @throws TwoFactorNotConfirmedException
     * @throws TwoFactorNotEnabledException
     */
    public function regenerateRecoveryCodes(User $user): array
    {
        if (! $user->hasEnabledTwoFactorAuthentication()) {
            throw new TwoFactorNotEnabledException();
        }

        if (is_null($user->two_factor_confirmed_at)) {
            throw new TwoFactorNotConfirmedException();
        }

        $codes = Collection::times(8, fn () => RecoveryCode::generate())->all();

        return $this->twoFactor->regenerateRecoveryCodes($user, $codes);
    }


    /**
     * @throws InvalidTwoFactorCodeException
     */
    public function confirmTwoFactor(User $user, string $code): void
    {
        $secret = $this->twoFactor->getSecret($user);

        if (! $secret || ! $this->twoFactorProvider->verify($secret, $code)) {
            throw new InvalidTwoFactorCodeException();
        }

        $this->twoFactor->confirm($user);
    }

    public function disableTwoFactor(User $user): void
    {
        $this->twoFactor->disable($user);
    }

    public function getRecoveryCodes(User $user): array
    {
        return $this->twoFactor->getRecoveryCodes($user);
    }


    /**
     * @throws InvalidTwoFactorCodeException
     */
    private function verifyTwoFactorCode(User $user, array $data): void
    {
        if (! empty($data['recovery_code'])) {
            $codes = $this->twoFactor->getRecoveryCodes($user);

            $index = array_search($data['recovery_code'], $codes, true);

            if ($index === false) {
                throw new InvalidTwoFactorCodeException();
            }

            unset($codes[$index]);
            $codes = array_values($codes);

            $this->twoFactor->regenerateRecoveryCodes($user, $codes);
            return;
        }

        if (! empty($data['two_factor_code'])) {
            $secret = $this->twoFactor->getSecret($user);

            if (! $secret || ! $this->twoFactorProvider->verify($secret, $data['two_factor_code'])) {
                throw new InvalidTwoFactorCodeException();
            }
        }
    }

    public function listSessions(User $user): array
    {
        return $this->tokens->list($user);
    }

    public function revokeSession(User $user, string $tokenId): void
    {
        $this->tokens->revoke($user, $tokenId);
    }

    public function revokeOtherSessions(User $user): void
    {
        $current = $this->tokens->current($user);

        if (! $current) {
            return;
        }

        $this->tokens->revokeOthers($user, (int) $current->id);
    }
}
