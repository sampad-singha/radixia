<?php

namespace Database\Seeders;

use App\Domain\Programs\Entities\Lesson;
use App\Domain\Programs\Entities\Module;
use App\Domain\Programs\Entities\Program;
use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Enums\CohortStatus;
use App\Models\User;
use Illuminate\Database\Seeder;

class ProgramSeeder extends Seeder
{
    public function run(): void
    {
        Program::factory()
            ->count(100)
            ->create()
            ->each(function ($program) {

                // Modules
                $modules = Module::factory()
                    ->count(rand(4, 10))
                    ->create([
                        'program_id' => $program->id
                    ]);

                // Lessons
                $modules->each(function ($module) {
                    Lesson::factory()
                        ->count(rand(6, 20))
                        ->create([
                            'module_id' => $module->id
                        ]);
                });

                // Past cohorts (1–2)
                Cohort::factory()
                    ->count(rand(1, 2))
                    ->create([
                        'program_id' => $program->id,
                        'assigned_instructor_id' => User::factory(),
                        'start_date' => now()->subMonths(rand(4, 10)),
                        'end_date' => now()->subMonths(rand(1, 3)),
                        'status' => CohortStatus::COMPLETED,
                    ]);

                // Future scheduled cohort (mandatory)
                Cohort::factory()
                    ->create([
                        'program_id' => $program->id,
                        'assigned_instructor_id' => User::factory(),
                        'start_date' => now()->addWeeks(rand(2, 8)),
                        'end_date' => now()->addWeeks(rand(10, 20)),
                        'status' => CohortStatus::SCHEDULED,
                    ]);
            });
    }
}
