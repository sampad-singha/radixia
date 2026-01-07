<?php

namespace App\Application\Auth\Services;

use App\Application\Mfa\MfaFactory;
use App\Domain\Auth\Exceptions\EmailAlreadyVerifiedException;
use App\Domain\Auth\Exceptions\EmailVerificationException;
use App\Domain\Auth\Exceptions\InvalidCredentialsException;
use App\Domain\Auth\Exceptions\InvalidResetClientException;
use App\Domain\Auth\Exceptions\InvalidTwoFactorCodeException;
use App\Domain\Auth\Exceptions\PasswordChangeException;
use App\Domain\Auth\Exceptions\PasswordConfirmationException;
use App\Domain\Auth\Exceptions\PasswordResetException;
use App\Domain\Auth\Repositories\AccessTokenRepositoryInterface;
use App\Domain\Auth\Services\AuthServiceInterface;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Models\User;
use App\Notifications\ResetPasswordNotification;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Contracts\Auth\PasswordBroker;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Laravel\Fortify\Contracts\CreatesNewUsers;
use Laravel\Fortify\Contracts\ResetsUserPasswords;
use Throwable;

class AuthService implements AuthServiceInterface
{
    public function __construct(
        private readonly UserRepositoryInterface $users,
        private readonly AccessTokenRepositoryInterface $tokens,
        private readonly CreatesNewUsers $createsNewUsers,
        private readonly ResetsUserPasswords $resetsUserPasswords,
        private readonly PasswordBroker $passwordBroker,
        private readonly MfaFactory $mfaFactory,
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
     * @throws Throwable
     */
    public function login(array $data, ?string $ip, ?string $userAgent): array
    {
        // 1. Credentials Check
        $user = $this->users->findByEmail($data['email']);

        if (! $user || ! Hash::check($data['password'], $user->password)) {
            throw new InvalidCredentialsException();
        }

        // 2. Check Enabled MFA Methods
        $enabledMethods = $user->mfaMethods->pluck('type')->toArray();

        if (! empty($enabledMethods)) {

            $requestedType = $data['mfa_type']
                ?? $user->mfaMethods()->where('is_default', true)->value('type')
                ?? $enabledMethods[0];

            $provider = $this->mfaFactory->make($requestedType);

            // A. VERIFY PHASE (Code Provided)
            if (! empty($data['mfa_code'])) {

                if (! in_array($requestedType, $enabledMethods)) {
                    throw new InvalidTwoFactorCodeException("Method not enabled.");
                }

                if ($provider->verify($user, $data['mfa_code'])) {
                    // Update usage timestamp
                    $user->mfaMethods()->where('type', $requestedType)->update(['last_used_at' => now()]);
                    goto issue_token;
                }

                throw new InvalidTwoFactorCodeException();
            }

            // B. CHALLENGE PHASE (No Code)
            $challengeSent = false;

            // Explicitly request challenge if type matches
            if (isset($data['mfa_type']) && $data['mfa_type'] === $requestedType) {
                $challengeSent = $provider->prepareChallenge($user);
            }

            return [
                'mfa_required' => true,
                'available_methods' => $enabledMethods,
                'challenge_sent' => $challengeSent,
                'message' => $challengeSent
                    ? "Challenge sent via {$requestedType}."
                    : "Two-factor authentication required."
            ];
        }

        issue_token:
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
            throw new InvalidResetClientException('Invalid password reset client.');
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
        $url = $resetUrlBase . '?token=' . urlencode($token) . '&email=' . urlencode($user->email);

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

    /**
     * @throws InvalidTwoFactorCodeException
     */
    private function verifyTwoFactorCode(User $user, array $data): ?int
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
            return count($codes);
        }

        if (! empty($data['two_factor_code'])) {
            $secret = $this->twoFactor->getSecret($user);

            if (! $secret || ! $this->twoFactorProvider->verify($secret, $data['two_factor_code'])) {
                throw new InvalidTwoFactorCodeException();
            }
        }
        return null;
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

    /**
     * @throws PasswordConfirmationException
     * @throws PasswordChangeException
     */
    public function changePassword(User $user, string $currentPassword, string $newPassword): void
    {
        if (! Hash::check($currentPassword, $user->password)) {
            throw new PasswordConfirmationException();
        }

        if (Hash::check($newPassword, $user->password)) {
            throw new PasswordChangeException("New password cannot be the same as your current password.");
        }

        $this->users->updatePassword($user, $newPassword);
        $user->tokens()->delete();
    }
}
