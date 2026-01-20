<?php

namespace App\Providers;

use App\Application\Auth\Services\AuthService;
use App\Application\Auth\Services\EmailChangeService;
use App\Application\Auth\Services\SocialAuthService;
use App\Application\Instructors\Services\InstructorProfileService;
use App\Application\Mfa\MfaFactory;
use App\Application\Mfa\Services\MfaService;
use App\Application\Users\Services\UserProfileService;
use App\Domain\Auth\Repositories\AccessTokenRepositoryInterface;
use App\Domain\Auth\Repositories\SocialAccountRepositoryInterface;
use App\Domain\Auth\Repositories\TwoFactorRepositoryInterface;
use App\Domain\Auth\Services\AuthServiceInterface;
use App\Domain\Auth\Services\EmailChangeServiceInterface;
use App\Domain\Auth\Services\SocialAuthServiceInterface;
use App\Domain\Instructors\Repositories\InstructorProfileRepositoryInterface;
use App\Domain\Instructors\Services\InstructorProfileServiceInterface;
use App\Domain\Mfa\Factories\MfaFactoryInterface;
use App\Domain\Mfa\Services\MfaServiceInterface;
use App\Domain\Users\Repositories\UserProfileRepositoryInterface;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Domain\Users\Services\UserProfileServiceInterface;
use App\Infrastructure\Auth\Repositories\SanctumAccessTokenRepository;
use App\Infrastructure\Auth\Repositories\SocialAccountRepository;
use App\Infrastructure\Auth\Repositories\TwoFactorRepository;
use App\Infrastructure\Instructors\Repositories\InstructorProfileRepository;
use App\Infrastructure\Users\Repositories\UserProfileRepository;
use App\Infrastructure\Users\Repositories\UserRepository;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // User & Authentication Bindings
        $this->app->bind(UserRepositoryInterface::class, UserRepository::class);
        $this->app->bind(AuthServiceInterface::class, AuthService::class);
        $this->app->bind(AccessTokenRepositoryInterface::class, SanctumAccessTokenRepository::class);
        $this->app->bind(TwoFactorRepositoryInterface::class, TwoFactorRepository::class);
        $this->app->bind(EmailChangeServiceInterface::class, EmailChangeService::class);
        $this->app->bind(SocialAccountRepositoryInterface::class, SocialAccountRepository::class);
        $this->app->bind(SocialAuthServiceInterface::class, SocialAuthService::class);
        $this->app->bind(MfaServiceInterface::class, MfaService::class);
        $this->app->bind(MfaFactoryInterface::class, MfaFactory::class);

        // User Profile Bindings
        $this->app->bind(UserProfileRepositoryInterface::class, UserProfileRepository::class);
        $this->app->bind(UserProfileServiceInterface::class, UserProfileService::class);

        // Instructor Profile Bindings
        $this->app->bind(InstructorProfileRepositoryInterface::class, InstructorProfileRepository::class);
        $this->app->bind(InstructorProfileServiceInterface::class, InstructorProfileService::class);

    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        VerifyEmail::createUrlUsing(function (object $notifiable) {

            // 1. Capture the Origin from the Registration/Resend request
            $origin = request()->header('Origin');
            $allowedOrigins = config('auth.allowed_origins', []);

            // 2. Validate Origin (Fallback to default if missing or unauthorized)
            $clientUrl = ($origin && in_array($origin, $allowedOrigins))
                ? $origin
                : config('app.frontend_url');

            // 3. Generate Signed URL with 'client_url' embedded
            return URL::temporarySignedRoute(
                'verification.verify',
                Carbon::now()->addMinutes(60),
                [
                    'id' => $notifiable->getKey(),
                    'hash' => hash('sha256', $notifiable->getEmailForVerification()),
                    'client_url' => $clientUrl, // <--- This is now signed and safe
                ]
            );
        });
    }
}
