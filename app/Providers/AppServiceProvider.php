<?php

namespace App\Providers;

use App\Application\Auth\Services\AuthService;
use App\Application\Auth\Services\EmailChangeService;
use App\Application\Auth\Services\SocialAuthService;
use App\Domain\Auth\Repositories\AccessTokenRepositoryInterface;
use App\Domain\Auth\Repositories\SocialAccountRepositoryInterface;
use App\Domain\Auth\Repositories\TwoFactorRepositoryInterface;
use App\Domain\Auth\Services\AuthServiceInterface;
use App\Domain\Auth\Services\EmailChangeServiceInterface;
use App\Domain\Auth\Services\SocialAuthServiceInterface;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Infrastructure\Auth\Repositories\SanctumAccessTokenRepository;
use App\Infrastructure\Auth\Repositories\SocialAccountRepository;
use App\Infrastructure\Auth\Repositories\TwoFactorRepository;
use App\Infrastructure\Users\Repositories\UserRepository;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->bind(UserRepositoryInterface::class, UserRepository::class);
        $this->app->bind(AuthServiceInterface::class, AuthService::class);
        $this->app->bind(AccessTokenRepositoryInterface::class, SanctumAccessTokenRepository::class);
        $this->app->bind(TwoFactorRepositoryInterface::class, TwoFactorRepository::class);
        $this->app->bind(EmailChangeServiceInterface::class, EmailChangeService::class);
        $this->app->bind(SocialAccountRepositoryInterface::class, SocialAccountRepository::class);
        $this->app->bind(SocialAuthServiceInterface::class, SocialAuthService::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }
}
