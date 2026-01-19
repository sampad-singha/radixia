<?php

namespace Database\Factories;

use App\Domain\Auth\Entities\SocialAccount;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

class SocialAccountFactory extends Factory
{
    protected $model = SocialAccount::class;

    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'provider' => 'google',
            'provider_id' => $this->faker->unique()->numerify('##########'),
            'avatar' => $this->faker->imageUrl(),
            'token' => $this->faker->sha256(),
        ];
    }
}
