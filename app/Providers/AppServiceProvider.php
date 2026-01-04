<?php

namespace App\Providers;

use App\Application\Auth\Services\AuthService;
use App\Application\Auth\Services\EmailChangeService;
use App\Domain\Auth\Repositories\AccessTokenRepositoryInterface;
use App\Domain\Auth\Repositories\TwoFactorRepositoryInterface;
use App\Domain\Auth\Services\AuthServiceInterface;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Domain\Users\Services\EmailChangeServiceInterface;
use App\Infrastructure\Auth\Repositories\SanctumAccessTokenRepository;
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
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }
}
