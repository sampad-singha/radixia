<?php

namespace Tests\Feature\Api\V1\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AuthSessionTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_list_sessions()
    {
        $user = User::factory()->create();
        $newToken = $user->createToken('Test Device');

        $response = $this->withToken($newToken->plainTextToken)->getJson('/api/v1/auth/sessions');

        $response->assertStatus(200)
            ->assertJsonStructure(['data' => [  // Change from ['data' => ['sessions']]
                [
                    'id',
                    'ip_address',
                    'name',
                    'last_used_at'  // Common session fields
                ]
            ]]);
    }

    public function test_user_can_revoke_specific_session()
    {
        $user = User::factory()->create();

        // Create two tokens
        $token1 = $user->createToken('Device 1');
        $token2 = $user->createToken('Device 2');

        // Authenticate with Token 2, try to revoke Token 1
        // Note: access the ID from the accessToken model property
        $token1Id = $token1->accessToken->id;

        $response = $this->withToken($token2->plainTextToken)
            ->deleteJson("/api/v1/auth/sessions/{$token1Id}");

        $response->assertStatus(200);

        $this->assertDatabaseMissing('personal_access_tokens', ['id' => $token1Id]);
        $this->assertDatabaseHas('personal_access_tokens', ['id' => $token2->accessToken->id]);
    }
}
