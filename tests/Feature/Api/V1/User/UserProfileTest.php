<?php

namespace Tests\Feature\Api\V1\User;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Tests\TestCase;

class UserProfileTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_view_own_basic_info()
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->getJson('/api/v1/auth/me');

        $response->assertStatus(200)
            ->assertJsonPath('data.user.email', $user->email);
    }

    public function test_user_can_update_account_information()
    {
        $user = User::factory()->create(['name' => 'Old Name']);

        $response = $this->actingAs($user)->putJson('/api/v1/user/account', [
            'name' => 'New Name',
            'email' => $user->email,
        ]);

        $response->assertStatus(200);
        $this->assertEquals('New Name', $user->fresh()->name);
    }

    public function test_user_can_change_password()
    {
        $user = User::factory()->create(['password' => Hash::make('old-password')]);
        $user->markEmailAsVerified();

        $response = $this->actingAs($user)->postJson('/api/v1/auth/change-password', [
            'current_password' => 'old-password',
            'password' => 'new-password',
            'password_confirmation' => 'new-password',
        ]);

        $response->assertStatus(200);
        $this->assertTrue(Hash::check('new-password', $user->fresh()->password));
    }

    public function test_user_cannot_change_password_with_invalid_current_password()
    {
        $user = User::factory()->create(['password' => Hash::make('old-password')]);
        $user->markEmailAsVerified();

        $response = $this->actingAs($user)->postJson('/api/v1/auth/change-password', [
            'current_password' => 'wrong-password',
            'password' => 'new-password',
            'password_confirmation' => 'new-password',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    public function test_user_can_request_email_change_with_sudo_mode()
    {
        Notification::fake();
        $user = User::factory()->create(['email' => 'old@radixia.com']);
        $user->markEmailAsVerified();

        // Simulate Active Sudo Mode
        $token = $user->createToken('test-token');
        $accessToken = $token->accessToken;
        $accessToken->sudo_expires_at = now()->addMinutes(10);
        $accessToken->save();

        config(['auth.email_change_timeout' => 60]); // Force integer 60

        $response = $this->withToken($token->plainTextToken)->postJson('/api/v1/user/email', [
            'email' => 'new@radixia.com',
        ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Verification code sent to the new email address.']);
    }
}
