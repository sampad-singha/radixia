<?php

namespace Database\Factories;

use App\Domain\Programs\Entities\Module;
use App\Domain\Programs\Entities\Program;
use Illuminate\Database\Eloquent\Factories\Factory;

class ModuleFactory extends Factory
{
    protected $model = Module::class;
    public function definition(): array
    {
        return [
            'program_id' => Program::factory(),

            'title' => $this->faker->sentence(3),

            'description' => $this->faker->optional()->paragraph(),

            'order_index' => $this->faker->numberBetween(1, 10),
        ];
    }
}
