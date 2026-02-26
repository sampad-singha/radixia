<?php

namespace App\Infrastructure\Meetings\Providers;

use App\Domain\Meetings\Services\MeetingWebhookServiceInterface;
use App\Domain\Meetings\Services\MeetRoomAccessServiceInterface;
use App\Infrastructure\Meetings\Jaas\Services\JaasMeetRoomAccessService;
use App\Infrastructure\Meetings\Jaas\Services\JaasWebhookService;
use Illuminate\Support\ServiceProvider;

class MeetingServiceProvider extends ServiceProvider
{
    /**
     * Register any application services (Bindings).
     */
    public function register(): void
    {
        /*------------------------------------------
         * Program Domain Bindings
         *------------------------------------------
         * */
        // Services
        $this->app->bind(MeetRoomAccessServiceInterface::class, JaasMeetRoomAccessService::class);
        $this->app->bind(MeetingWebhookServiceInterface::class, JaasWebhookService::class);
    }

    /**
     * Bootstrap any application services (Policies, Routes, Observers).
     */
    public function boot(): void
    {
        // Register the Policy
    }
}