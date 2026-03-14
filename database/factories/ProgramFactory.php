<?php

namespace Database\Factories;

use App\Domain\Programs\Entities\Program;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<Program>
 */
class ProgramFactory extends Factory
{
    protected $model = Program::class;
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $title = $this->faker->unique()->sentence(3);

        return [
            'title' => $title,
            'slug' => Str::slug($title),

            'description' => $this->faker->paragraphs(3, true),
            'short_description' => $this->faker->sentence(12),

            'level' => $this->faker->randomElement([
                'beginner',
                'intermediate',
                'advanced'
            ]),

            'thumbnail_url' => 'https://x-picsum.photos/seed/'.$this->faker->uuid.'/640/360',

            'intro_video_url' => $this->faker->url(),

            'status' => 'published',

            'instructor_id' => User::factory(),
        ];
    }

    public function published(): static
    {
        return $this->state(fn() => [
            'status' => 'published'
        ]);
    }

    public function draft(): static
    {
        return $this->state(fn() => [
            'status' => 'draft'
        ]);
    }
}
