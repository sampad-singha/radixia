<?php

namespace Tests\Feature\Api\V1\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class AuthenticationTest extends TestCase
{
    use RefreshDatabase; // Automatically migrates/resets DB for each test

    public function test_user_can_register()
    {
        // Act: Hit the register endpoint
        $response = $this->postJson('/api/v1/auth/register', [
            'name' => 'Sampad Singha',
            'email' => 'sampad@radixia.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
            'device_name' => 'Chrome',
            'marketing_opt_in' => true,
        ]);

        // Assert: Check status and structure
        $response->assertStatus(201)
            ->assertJsonStructure([
                'data' => [
                    'user' => ['id', 'email', 'name'],
                    'token'
                ]
            ]);

        // Assert: Check Database
        $this->assertDatabaseHas('users', ['email' => 'sampad@radixia.com']);
    }

    public function test_user_can_login()
    {
        // Arrange: Create a user manually
        $user = User::factory()->create([
            'email' => 'login@radixia.com',
            'password' => Hash::make('password123'),
        ]);

        // Act: Hit login endpoint
        $response = $this->postJson('/api/v1/auth/login', [
            'email' => 'login@radixia.com',
            'password' => 'password123',
            'device_name' => 'test-device'
        ]);

        // Assert
        $response->assertStatus(200)
            ->assertJsonStructure(['data' => ['token']]);
    }

    public function test_user_cannot_login_with_invalid_credentials()
    {
        // Arrange
        $user = User::factory()->create([
            'password' => Hash::make('correct-password'),
        ]);

        // Act: Wrong password
        $response = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'wrong-password',
            'device_name' => 'test-device'
        ]);

        // Assert: Match the actual response structure
        $response->assertStatus(401)
            ->assertJson([
                'message' => 'The provided credentials are incorrect.', // <--- Updated message
                'code' => 'INVALID_CREDENTIALS'                        // <--- Added code check
            ]);
    }

    public function test_registration_validates_required_fields()
    {
        // Act: Send empty data
        $response = $this->postJson('/api/v1/auth/register', []);

        // Assert: Validation errors
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'email', 'password', 'device_name']);
    }
}
