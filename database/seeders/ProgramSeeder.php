<?php

namespace Database\Seeders;

use App\Domain\Instructors\Entities\InstructorProfile;
use App\Domain\Programs\Entities\Program;
use App\Domain\Programs\Entities\Module;
use App\Domain\Programs\Entities\Lesson;
use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Entities\CohortEnrollment;
use App\Domain\Programs\Enums\CohortStatus;
use App\Domain\Taxonomy\Entities\Category;
use App\Domain\Taxonomy\Entities\Subcategory;
use App\Domain\Taxonomy\Entities\Topic;
use App\Domain\Taxonomy\Entities\Language;
use App\Domain\Taxonomy\Entities\Review;
use App\Models\User;
use Illuminate\Database\Seeder;

class ProgramSeeder extends Seeder
{
    public function run(): void
    {
        // --------------------------------------------------
        // Languages
        // --------------------------------------------------

        $english = Language::create([
            'name' => 'English',
            'code' => 'en'
        ]);

        $bangla = Language::create([
            'name' => 'Bengali',
            'code' => 'bn'
        ]);

        // --------------------------------------------------
        // Categories / Subcategories / Topics
        // --------------------------------------------------

        $webDev = Category::create([
            'name' => 'Web Development',
            'slug' => 'web-development'
        ]);

        $backend = Subcategory::create([
            'name' => 'Backend',
            'slug' => 'backend',
            'category_id' => $webDev->id
        ]);

        $frontend = Subcategory::create([
            'name' => 'Frontend',
            'slug' => 'frontend',
            'category_id' => $webDev->id
        ]);

        $topics = collect([
            Topic::create([
                'name' => 'Laravel',
                'slug' => 'laravel',
                'subcategory_id' => $backend->id
            ]),
            Topic::create([
                'name' => 'API Development',
                'slug' => 'api-development',
                'subcategory_id' => $backend->id
            ]),
            Topic::create([
                'name' => 'React',
                'slug' => 'react',
                'subcategory_id' => $frontend->id
            ]),
            Topic::create([
                'name' => 'Vue.js',
                'slug' => 'vue-js',
                'subcategory_id' => $frontend->id
            ]),
        ]);

        // --------------------------------------------------
        // Students
        // --------------------------------------------------

        $students = User::factory()->count(40)->create();

        // --------------------------------------------------
        // Instructors
        // --------------------------------------------------

        $instructors = User::factory()
            ->count(5)
            ->create();

        $instructors->each(function ($user) {

            InstructorProfile::create([
                'user_id' => $user->id,
                'headline' => fake()->randomElement([
                    'Senior Laravel Engineer',
                    'Backend Architect',
                    'Fullstack Developer'
                ]),
                'bio' => fake()->paragraph(),
                'intro_video_url' => fake()->url(),
                'is_verified' => true,
                'verification_status' => 'approved',
            ]);

        });

        $profiles = InstructorProfile::all();

        $profiles->each(function ($profile) use ($students) {

            $students->random(rand(5, 15))
                ->each(function ($student) use ($profile) {

                    Review::create([
                        'user_id' => $student->id,
                        'reviewable_id' => $profile->id,
                        'reviewable_type' => InstructorProfile::class,
                        'rating' => rand(3, 5),
                        'comment' => fake()->sentence(),
                        'is_approved' => true,
                    ]);

                });

        });


        // --------------------------------------------------
        // Programs
        // --------------------------------------------------

        Program::factory()
            ->count(15)
            ->create([
                'language_id' => $english->id,
            ])
            ->each(function ($program) use ($topics, $students, $instructors) {

                $program->update([
                    'instructor_id' => $instructors->random()->id
                ]);

                // Attach topics
                $program->topics()->attach(
                    $topics->random(rand(1,2))->pluck('id')
                );

                // --------------------------------------------------
                // Modules
                // --------------------------------------------------

                $modules = Module::factory()
                    ->count(rand(4, 8))
                    ->create([
                        'program_id' => $program->id
                    ]);

                // --------------------------------------------------
                // Lessons
                // --------------------------------------------------

                $modules->each(function ($module) {

                    Lesson::factory()
                        ->count(rand(6, 12))
                        ->create([
                            'module_id' => $module->id
                        ]);

                });

                // --------------------------------------------------
                // Cohorts
                // --------------------------------------------------

                $pastCohorts = Cohort::factory()
                    ->count(rand(1,2))
                    ->create([
                        'program_id' => $program->id,
                        'assigned_instructor_id' => $program->instructor_id,
                        'start_date' => now()->subMonths(rand(4,10)),
                        'end_date' => now()->subMonths(rand(1,3)),
                        'status' => CohortStatus::COMPLETED
                    ]);

                $futureCohort = Cohort::factory()
                    ->create([
                        'program_id' => $program->id,
                        'assigned_instructor_id' => $program->instructor_id,
                        'start_date' => now()->addWeeks(rand(2,6)),
                        'end_date' => now()->addWeeks(rand(10,20)),
                        'status' => CohortStatus::SCHEDULED
                    ]);

                // --------------------------------------------------
                // Enrollments
                // --------------------------------------------------

                $pastCohorts->each(function ($cohort) use ($students) {

                    $students->random(rand(5,15))
                        ->each(function ($student) use ($cohort) {

                            CohortEnrollment::create([
                                'cohort_id' => $cohort->id,
                                'user_id' => $student->id,
                                'status' => 'active'
                            ]);

                        });

                });

                $futureCohort->enrollments()->createMany(
                    $students->random(rand(5,15))
                        ->map(function ($student) {
                            return [
                                'user_id' => $student->id,
                                'status' => 'active'
                            ];
                        })
                        ->toArray()
                );

                // --------------------------------------------------
                // Reviews
                // --------------------------------------------------

                $students->random(rand(5,15))
                    ->each(function ($student) use ($program) {

                        Review::create([
                            'user_id' => $student->id,
                            'reviewable_id' => $program->id,
                            'reviewable_type' => Program::class,
                            'rating' => rand(3,5),
                            'comment' => fake()->sentence(),
                            'is_approved' => true
                        ]);

                    });

                // --------------------------------------------------
                // Features
                // --------------------------------------------------

                $program->features()->createMany([
                    [
                        'content' => '27 hours of video content',
                        'icon' => 'Video',
                        'order_index' => 1
                    ],
                    [
                        'content' => 'Certificate of completion',
                        'icon' => 'Award',
                        'order_index' => 2
                    ],
                    [
                        'content' => 'Full lifetime access',
                        'icon' => 'Infinity',
                        'order_index' => 3
                    ],
                ]);

                // --------------------------------------------------
                // Content Blocks
                // --------------------------------------------------

                $program->contentBlocks()->createMany([
                    [
                        'type' => 'learning_outcome',
                        'content' => 'Build scalable Laravel applications',
                        'order_index' => 1
                    ],
                    [
                        'type' => 'learning_outcome',
                        'content' => 'Understand Domain Driven Design',
                        'order_index' => 2
                    ],
                    [
                        'type' => 'prerequisite',
                        'content' => 'Basic Laravel knowledge',
                        'order_index' => 1
                    ],
                    [
                        'type' => 'target_audience',
                        'content' => 'Backend developers',
                        'order_index' => 1
                    ]
                ]);
            });
    }
}
