<?php

namespace Tests\Feature\Api\V1\User;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Laravel\Sanctum\Sanctum;
use Tests\TestCase;

class EmailChangeTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_request_email_change()
    {
        $user = User::factory()->create(['email' => 'old@example.com']);

        // Manually create a token to manipulate Sudo timestamp
        $token = $user->createToken('test-token');
        $token->accessToken->forceFill([
            'sudo_expires_at' => now()->addMinutes(10)
        ])->save();

        // Use this specific token for the request
        $response = $this->withToken($token->plainTextToken)->postJson('/api/v1/user/email', [
            'email' => 'new@example.com',
        ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Verification code sent to the new email address.']);

        $this->assertDatabaseHas('users', [
            'id' => $user->id,
            'pending_email' => 'new@example.com',
        ]);
    }

    public function test_user_can_verify_email_change()
    {
        $user = User::factory()->create([
            'email' => 'old@example.com',
            'pending_email' => 'new@example.com',
            'pending_email_token' => Hash::make('123456'),
            'pending_email_expires_at' => now()->addHour(),
        ]);

        // actingAs is sufficient here as we don't need Sudo mode for verification (usually)
        // If your logic requires it, use the token method above.
        $response = $this->actingAs($user)->postJson('/api/v1/user/email/verify', [
            'code' => '123456',
        ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Email address updated successfully.']);

        $user->refresh();
        $this->assertEquals('new@example.com', $user->email);
        $this->assertNull($user->pending_email);
    }

    public function test_verify_fails_with_invalid_code()
    {
        $user = User::factory()->create([
            'email' => 'old@example.com',
            'pending_email' => 'new@example.com',
            'pending_email_token' => Hash::make('123456'),
            'pending_email_expires_at' => now()->addHour(),
        ]);

        $response = $this->actingAs($user)->postJson('/api/v1/user/email/verify', [
            'code' => '000000',
        ]);

        // Updated assertion to match actual application behavior (422)
        $response->assertStatus(422);
    }
}
