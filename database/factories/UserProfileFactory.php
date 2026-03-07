<?php

namespace Database\Factories;

use App\Domain\Users\Entities\UserProfile;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<UserProfile>
 */
class UserProfileFactory extends Factory
{
    protected $model = UserProfile::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'avatar_url' => $this->faker->imageUrl(200, 200, 'people'),
            'bio' => $this->faker->paragraph(),
            'city' => $this->faker->city(),
            'country' => $this->faker->country(),
            'timezone' => $this->faker->timezone(),
            'locale' => $this->faker->randomElement(['en', 'bn']),
            'gender' => $this->faker->randomElement(['male', 'female', 'other']),
            'date_of_birth' => $this->faker->date('Y-m-d', '-18 years'),
            'marketing_opt_in' => $this->faker->boolean(20), // 20% chance of true
        ];
    }
}
