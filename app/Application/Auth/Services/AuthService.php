<?php

namespace App\Application\Auth\Services;

use App\Domain\Auth\Exceptions\EmailAlreadyVerifiedException;
use App\Domain\Auth\Exceptions\EmailVerificationException;
use App\Domain\Auth\Exceptions\InvalidCredentialsException;
use App\Domain\Auth\Exceptions\InvalidTwoFactorCodeException;
use App\Domain\Auth\Exceptions\PasswordConfirmationException;
use App\Domain\Auth\Exceptions\PasswordResetException;
use App\Domain\Auth\Exceptions\PasswordResetLinkException;
use App\Domain\Auth\Services\AuthServiceInterface;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Contracts\Auth\PasswordBroker;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Laravel\Fortify\Contracts\CreatesNewUsers;
use Laravel\Fortify\Contracts\ResetsUserPasswords;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;
use Laravel\Fortify\RecoveryCode;
use Laravel\Sanctum\PersonalAccessToken;

class AuthService implements AuthServiceInterface
{
    public function __construct(
        private readonly UserRepositoryInterface $users,
        private readonly CreatesNewUsers $createsNewUsers,
        private readonly ResetsUserPasswords $resetsUserPasswords,
        private readonly PasswordBroker $passwordBroker,
        private readonly TwoFactorAuthenticationProvider $twoFactorProvider,
    ) {}

    public function register(array $data): array
    {
        $user = $this->createsNewUsers->create($data);

        event(new Registered($user));

        $token = $user->createToken($data['device_name'])->plainTextToken;

        return ['user' => $user, 'token' => $token];
    }

    /**
     * @throws EmailVerificationException
     */
    public function verifyEmail(int $id, string $hash): bool
    {
        $user = $this->users->findById($id);

        $emailForVerification = $user
            ? $user->getEmailForVerification()
            : 'email_verification_dummy_value';

        $expectedHash = sha1($emailForVerification);

        $hashMatches = hash_equals(
            $expectedHash,
            (string) $hash
        );

        if (! $user || ! $hashMatches) {
            throw new EmailVerificationException();
        }

        if ($user->hasVerifiedEmail()) {
            return true;
        }

        if ($user->markEmailAsVerified()) {
            event(new Verified($user));
        }

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
     * @throws InvalidCredentialsException
     */
    public function login(array $data): array
    {
        $user = $this->users->findByEmail($data['email']);

        if (! $user || ! Hash::check($data['password'], $user->password)) {
            throw new InvalidCredentialsException();
        }

        // Check if 2FA is enabled and confirmed
        if ($user->hasEnabledTwoFactorAuthentication()) {
            // Check if code is provided in request
            if (empty($data['two_factor_code']) && empty($data['recovery_code'])) {
                return [
                    'two_factor_required' => true,
                    'message' => 'Two-factor authentication required.'
                ];
            }

            $this->verifyTwoFactorCode($user, $data);
        }

        $token = $user->createToken($data['device_name'])->plainTextToken;

        return ['user' => $user, 'token' => $token];
    }

    public function logout(User $user): void
    {
        $user->currentAccessToken()?->delete();
    }

    /**
     * @throws PasswordResetLinkException
     */
    public function forgotPassword(array $data): string
    {
        $status = $this->passwordBroker->sendResetLink(['email' => $data['email']]);

        if ($status !== Password::RESET_LINK_SENT) {
            throw new PasswordResetLinkException(__($status));
        }

        return __($status);
    }

    /**
     * @throws PasswordResetException
     */
    public function resetPassword(array $data): string
    {
        $status = $this->passwordBroker->reset(
            $data,
            function ($user, $password) {
                $this->resetsUserPasswords->reset($user, ['password' => $password]);
            }
        );

        if ($status !== Password::PASSWORD_RESET) {
            throw new PasswordResetException(__($status));
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

        // Get the specific token used for this request
        /** @var PersonalAccessToken $token */
        $token = $user->currentAccessToken();

        // If no token (e.g., testing or cookie session), you might handle differently
        // But for API strict mode:
        if ($token instanceof PersonalAccessToken) {
            $token->forceFill([
                'sudo_expires_at' => now()->addSeconds(config('auth.password_timeout', 600)),
            ])->save();
        }

        return true;
    }

    public function passwordConfirmedStatus(User $user): bool
    {
        /** @var PersonalAccessToken $token */
        $token = $user->currentAccessToken();

        if (! $token instanceof PersonalAccessToken) {
            return false;
        }

        // Check if timestamp exists and is in the future
        return $token->sudo_expires_at && $token->sudo_expires_at->isFuture();
    }

    public function enableTwoFactor(User $user): array
    {
        // 1. Generate Secret (Server-side, secure)
        $secretKey = $this->twoFactorProvider->generateSecretKey();

        // 2. Encrypt & Store
        $user->forceFill([
            'two_factor_secret' => encrypt($secretKey),
            'two_factor_recovery_codes' => encrypt(json_encode(
                Collection::times(8, fn () => RecoveryCode::generate())->all()
            )),
        ])->save();

        // 3. Construct Data (The URL)
        $appName = config('app.name');
        $otpAuthUrl = sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s',
            rawurlencode($appName),
            rawurlencode($user->email),
            $secretKey,
            rawurlencode($appName)
        );

        // 4. Return Data
        return [
            'two_factor_url' => $otpAuthUrl, // Frontend renders this
            'secret' => $secretKey,
            'recovery_codes' => json_decode(decrypt($user->two_factor_recovery_codes)),
        ];
    }

    public function regenerateRecoveryCodes(User $user): array
    {
        $user->forceFill([
            'two_factor_recovery_codes' => encrypt(json_encode(
                Collection::times(8, fn () => RecoveryCode::generate())->all()
            )),
        ])->save();

        return json_decode(decrypt($user->two_factor_recovery_codes));
    }

    /**
     * @throws InvalidTwoFactorCodeException
     */
    public function confirmTwoFactor(User $user, string $code): void
    {
        if (! $this->twoFactorProvider->verify(decrypt($user->two_factor_secret), $code)) {
            throw new InvalidTwoFactorCodeException();
        }

        $user->forceFill([
            'two_factor_confirmed_at' => now(),
        ])->save();
    }

    public function disableTwoFactor(User $user): void
    {
        $user->forceFill([
            'two_factor_secret' => null,
            'two_factor_recovery_codes' => null,
            'two_factor_confirmed_at' => null,
        ])->save();
    }

    public function getRecoveryCodes(User $user): array
    {
        if (! $user->two_factor_recovery_codes) {
            return [];
        }
        return json_decode(decrypt($user->two_factor_recovery_codes));
    }


    /**
     * @throws InvalidTwoFactorCodeException
     */
    private function verifyTwoFactorCode(User $user, array $data): void
    {
        if (! empty($data['recovery_code'])) {
            // Decrypt codes
            $recoveryCodes = json_decode(decrypt($user->two_factor_recovery_codes), true);

            // Search for the code
            $index = array_search($data['recovery_code'], $recoveryCodes);

            if ($index === false) {
                throw new InvalidTwoFactorCodeException();
            }

            // Remove used code and generate a new one (optional, or just remove)
            unset($recoveryCodes[$index]);
            // Re-index array
            $recoveryCodes = array_values($recoveryCodes);

            // Save updated codes
            $user->forceFill([
                'two_factor_recovery_codes' => encrypt(json_encode($recoveryCodes)),
            ])->save();

        } elseif (! empty($data['two_factor_code'])) {
            // Verify Time-Based OTP
            if (! $this->twoFactorProvider->verify(decrypt($user->two_factor_secret), $data['two_factor_code'])) {
                throw new InvalidTwoFactorCodeException();
            }
        }
    }
}
