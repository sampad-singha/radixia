<?php

namespace App\Infrastructure\Catalog\Providers;

use App\Domain\Catalog\Repositories\CatalogRepositoryInterface;
use App\Infrastructure\Catalog\Repositories\CatalogRepository;
use Illuminate\Support\ServiceProvider;

class CatalogServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        /*------------------------------------------
         * Catalog Domain Bindings
         *------------------------------------------
         * */
        // Repositories
        $this->app->bind(CatalogRepositoryInterface::class, CatalogRepository::class);

    }

    /**
     * Bootstrap any application services (Policies, Routes, Observers).
     */
    public function boot(): void
    {
        // Register the Policy
    }
}
