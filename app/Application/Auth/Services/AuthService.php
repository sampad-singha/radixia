<?php

namespace App\Application\Auth\Services;

use App\Domain\Auth\Exceptions\EmailAlreadyVerifiedException;
use App\Domain\Auth\Exceptions\EmailVerificationException;
use App\Domain\Auth\Exceptions\InvalidCredentialsException;
use App\Domain\Auth\Exceptions\PasswordAlreadySetException;
use App\Domain\Auth\Exceptions\PasswordChangeException;
use App\Domain\Auth\Exceptions\PasswordConfirmationException;
use App\Domain\Auth\Exceptions\PasswordNotSetException;
use App\Domain\Auth\Exceptions\PasswordResetException;
use App\Domain\Auth\Repositories\AccessTokenRepositoryInterface;
use App\Domain\Auth\Services\AuthServiceInterface;
use App\Domain\Mfa\Services\MfaServiceInterface;
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

readonly class AuthService implements AuthServiceInterface
{
    public function __construct(
        private UserRepositoryInterface        $users,
        private AccessTokenRepositoryInterface $tokens,
        private CreatesNewUsers                $createsNewUsers,
        private ResetsUserPasswords            $resetsUserPasswords,
        private PasswordBroker                 $passwordBroker,
        private MfaServiceInterface            $mfaService,
    )
    {
    }

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
    public function verifyEmail(string $id, string $hash): bool
    {
        $user = $this->users->findById($id);

        $emailForVerification = $user ? $user->getEmailForVerification() : 'email_verification_dummy_value';
        $expectedHash = hash('sha256', $emailForVerification);

        if (!$user || !hash_equals($expectedHash, (string)$hash)) {
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
     * @throws InvalidCredentialsException
     * @throws Throwable
     */
    public function login(array $data, ?string $ip, ?string $userAgent): array
    {
        // 1. Credentials Check
        $user = $this->users->findByEmail($data['email']);
        if (!$user || !Hash::check($data['password'], $user->password)) {
            throw new InvalidCredentialsException();
        }

        // 2. Check MFA
        $mfaResult = $this->mfaService->checkMfaRequirement($user, $data);

        dd($mfaResult);

        if ($mfaResult) {
            // --- MISSING PART: Create Temp Token ---
            $tempToken = $this->tokens->create(
                $user,
                'login-mfa-pending', // Name matters!
                $ip,
                $userAgent,
                ['mfa:verify']  // Ability to identify this as a temp token
            );

            // Add token to result so Controller can send it
            $mfaResult['token'] = $tempToken;
            return $mfaResult;
        }

        // 3. Issue Token
        $token = $this->tokens->create($user, $data['device_name'], $ip, $userAgent);
        $user->unsetRelation('mfaMethods');

        return ['user' => $user, 'token' => $token];
    }

    public function logout(User $user): void
    {
        $currentToken = $this->tokens->current($user);

        if ($currentToken) {
            $this->tokens->revoke($user, (string)$currentToken->id);
        }
    }

    public function forgotPassword(array $data, ?string $origin): string
    {
        $allowedOrigins = config('auth.allowed_origins', []);

        // If origin is valid, use it. Otherwise, fallback to default frontend URL.
        $baseUrl = ($origin && in_array($origin, $allowedOrigins))
            ? $origin
            : config('app.frontend_url');

        // 2. Get the user
        $user = $this->users->findByEmail($data['email']);

        if (!$user) {
            return Password::RESET_LINK_SENT;
        }

        // 3. Generate Token
        $token = Password::broker()->createToken($user);

        // 4. Build URL (Assume '/reset-password' path is standard for all frontends)
        $url = $baseUrl . '/reset-password?token=' . urlencode($token) . '&email=' . urlencode($user->email);

        // 5. Send Notification
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
     * @throws PasswordNotSetException
     */
    public function confirmSudoMode(User $user, string $type, string $value): void
    {
        if ($type === 'password') {
            if (!$user->is_password_set) {
                throw new PasswordNotSetException();
            }
            if (!$user->password || !Hash::check($value, $user->password)) {
                throw new PasswordConfirmationException();
            }
        } else {
            // Re-use your MFA verification logic
            // This validates the code AND that the method is enabled for the user
            $this->mfaService->verifyMfaChallenge($user, $value, $type);
        }

        // Success: Extend Sudo Mode
        $token = $this->tokens->current($user);
        $this->tokens->setSudoExpiration($token, config('auth.password_timeout', 10800));
    }


    public function getSudoStatus(User $user): array
    {
        $isSudo = $this->tokens->isSudoActive($user);

        if ($isSudo) {
            return ['confirmed' => true];
        }

        // If not sudo, calculate available methods
        $methods = [];

        // 1. Password available?
        if ($user->is_password_set && $user->password) {
            $methods[] = 'password';
        }

        // 2. MFA methods available?
        $user->load('mfaMethods');
        $mfaMethods = $user->mfaMethods->pluck('type')->toArray();

        $methods = array_merge($methods, $mfaMethods);

        if (empty($methods)) {
            $methods[] = 'email';
        }

        return [
            'confirmed' => false,
            'available_methods' => array_unique($methods)
        ];
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

        if (!$current) {
            return;
        }

        $this->tokens->revokeOthers($user, (int)$current->id);
    }

    /**
     * @throws PasswordConfirmationException
     * @throws PasswordChangeException
     */
    public function changePassword(User $user, string $currentPassword, string $newPassword): void
    {
        if (!Hash::check($currentPassword, $user->password)) {
            throw new PasswordConfirmationException();
        }

        if (Hash::check($newPassword, $user->password)) {
            throw new PasswordChangeException("New password cannot be the same as your current password.");
        }

        $this->users->updatePassword($user, $newPassword);
        $user->tokens()->delete();
    }

    /**
     * @throws PasswordAlreadySetException
     */
    public function setPassword(User $user, string $password): void
    {
        if ($user->is_password_set) {
            throw new PasswordAlreadySetException("User already has a password.");
        }

        $user->forceFill([
            'password' => Hash::make($password),
            'is_password_set' => true,
        ])->save();
    }
}
