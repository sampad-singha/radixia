<?php

namespace Database\Factories;

use App\Domain\Programs\Entities\Lesson;
use App\Domain\Programs\Entities\Module;
use Illuminate\Database\Eloquent\Factories\Factory;

class LessonFactory extends Factory
{
    protected $model = Lesson::class;
    public function definition(): array
    {
        return [
            'module_id' => Module::factory(),
            'title' => $this->faker->sentence(3),
            'description' => $this->faker->optional()->paragraph(),
            'duration_minutes' => $this->faker->numberBetween(5, 60),
            'order_index' => $this->faker->numberBetween(1, 20),
        ];
    }
}
