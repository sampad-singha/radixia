<?php

namespace Database\Factories;

use App\Domain\Mfa\Entities\MfaMethod;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

class MfaMethodFactory extends Factory
{
    protected $model = MfaMethod::class;

    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'type' => 'totp',
            'secret' => 'ONSWG4TFORBV642V', // Dummy base32 secret
            'last_used_at' => null,
        ];
    }
}
