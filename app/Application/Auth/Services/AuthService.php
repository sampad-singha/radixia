<?php

namespace App\Application\Auth\Services;

use App\Domain\Auth\Exceptions\EmailAlreadyVerifiedException;
use App\Domain\Auth\Exceptions\EmailVerificationException;
use App\Domain\Auth\Exceptions\InvalidCredentialsException;
use App\Domain\Auth\Exceptions\PasswordConfirmationException;
use App\Domain\Auth\Exceptions\PasswordResetException;
use App\Domain\Auth\Exceptions\PasswordResetLinkException;
use App\Domain\Auth\Services\AuthServiceInterface;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Models\User;
use Exception;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Contracts\Auth\PasswordBroker;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Laravel\Fortify\Contracts\CreatesNewUsers;
use Laravel\Fortify\Contracts\ResetsUserPasswords;
use Laravel\Sanctum\PersonalAccessToken;

class AuthService implements AuthServiceInterface
{
    public function __construct(
        private readonly UserRepositoryInterface $users,
        private readonly CreatesNewUsers $createsNewUsers,
        private readonly ResetsUserPasswords $resetsUserPasswords,
        private readonly PasswordBroker $passwordBroker
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
        $user = $this->users->findById($id); // Assuming findById exists or use findByEmail logic

        if (! $user || ! hash_equals((string) $hash, sha1($user->getEmailForVerification()))) {
            throw new EmailVerificationException('Invalid or expired verification link.');
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
     * @throws Exception
     */
    public function resendVerificationNotification(User $user): void
    {
        if ($user->hasVerifiedEmail()) {
            throw new EmailAlreadyVerifiedException();
        }

        $user->sendEmailVerificationNotification();
    }

    /**
     * @throws Exception
     */
    public function login(array $data): array
    {
        $user = $this->users->findByEmail($data['email']);

        if (! $user || ! Hash::check($data['password'], $user->password)) {
            throw new InvalidCredentialsException();
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
                'sudo_expires_at' => now()->addSeconds(config('auth.password_timeout', 10800)),
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
}
