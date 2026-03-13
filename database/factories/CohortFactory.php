<?php

namespace Database\Factories;

use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Entities\Program;
use App\Domain\Programs\Enums\CohortStatus;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Cohort>
 */
class CohortFactory extends Factory
{
    protected $model = Cohort::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $start = $this->faker->dateTimeBetween('+1 week', '+6 months');
        $end = (clone $start)->modify('+' . rand(30, 90) . ' days');

        return [
            'program_id' => Program::factory(),
            'assigned_instructor_id' => User::factory(),
            'name' => 'Batch ' . $this->faker->unique()->numberBetween(1, 999),
            'start_date' => $start,
            'end_date' => $end,
            'capacity' => $this->faker->numberBetween(20, 100),
            'price' => $this->faker->randomFloat(2, 500, 5000),
            'status' => $this->faker->randomElement([
                CohortStatus::SCHEDULED,
                CohortStatus::ACTIVE,
            ]),
        ];
    }
}
