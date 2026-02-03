<?php

namespace App\Infrastructure\Programs\Providers;

use App\Application\Programs\Services\CohortEnrollmentService;
use App\Application\Programs\Services\CohortService;
use App\Application\Programs\Services\CohortSessionService;
use App\Application\Programs\Services\JitsiMeetRoomAccessService;
use App\Application\Programs\Services\ProgramService;
use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Entities\CohortSession;
use App\Domain\Programs\Entities\Lesson;
use App\Domain\Programs\Entities\Module;
use App\Domain\Programs\Entities\Program;
use App\Domain\Programs\Repositories\CohortEnrollmentRepositoryInterface;
use App\Domain\Programs\Repositories\CohortRepositoryInterface;
use App\Domain\Programs\Repositories\CohortSessionRepositoryInterface;
use App\Domain\Programs\Repositories\LessonRepositoryInterface;
use App\Domain\Programs\Repositories\ModuleRepositoryInterface;
use App\Domain\Programs\Repositories\ProgramRepositoryInterface;
use App\Domain\Programs\Services\CohortEnrollmentServiceInterface;
use App\Domain\Programs\Services\CohortServiceInterface;
use App\Domain\Programs\Services\CohortSessionServiceInterface;
use App\Domain\Programs\Services\MeetRoomAccessServiceInterface;
use App\Domain\Programs\Services\ProgramServiceInterface;
use App\Infrastructure\Programs\Repositories\CohortEnrollmentRepository;
use App\Infrastructure\Programs\Repositories\CohortRepository;
use App\Infrastructure\Programs\Repositories\CohortSessionRepository;
use App\Infrastructure\Programs\Repositories\LessonRepository;
use App\Infrastructure\Programs\Repositories\ModuleRepository;
use App\Infrastructure\Programs\Repositories\ProgramRepository;
use App\Policies\Program\CohortPolicy;
use App\Policies\Program\CohortSessionPolicy;
use App\Policies\Program\LessonPolicy;
use App\Policies\Program\ModulePolicy;
use App\Policies\Program\ProgramPolicy;
use Carbon\Laravel\ServiceProvider;
use Illuminate\Support\Facades\Gate;

class ProgramServiceProvider extends ServiceProvider
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
        // Repositories
        $this->app->bind(ProgramRepositoryInterface::class, ProgramRepository::class);
        $this->app->bind(CohortRepositoryInterface::class, CohortRepository::class);
        $this->app->bind(ModuleRepositoryInterface::class, ModuleRepository::class);
        $this->app->bind(LessonRepositoryInterface::class, LessonRepository::class);
        $this->app->bind(CohortSessionRepositoryInterface::class, CohortSessionRepository::class);
        $this->app->bind(CohortEnrollmentRepositoryInterface::class, CohortEnrollmentRepository::class);
        // Services
        $this->app->bind(ProgramServiceInterface::class, ProgramService::class);
        $this->app->bind(CohortServiceInterface::class, CohortService::class);
        $this->app->bind(CohortEnrollmentServiceInterface::class, CohortEnrollmentService::class);
        $this->app->bind(CohortSessionServiceInterface::class, CohortSessionService::class);
        $this->app->bind(MeetRoomAccessServiceInterface::class, JitsiMeetRoomAccessService::class);
    }

    /**
     * Bootstrap any application services (Policies, Routes, Observers).
     */
    public function boot(): void
    {
        // Register the Policy
        Gate::policy(Program::class, ProgramPolicy::class);
        Gate::policy(Module::class, ModulePolicy::class);
        Gate::policy(Lesson::class, LessonPolicy::class);
        Gate::policy(Cohort::class, CohortPolicy::class);
        Gate::policy(CohortSession::class, CohortSessionPolicy::class);
    }
}