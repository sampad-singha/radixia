<?php

namespace Tests\Feature\Api\V1\Auth;

use App\Domain\Auth\Services\SocialAuthServiceInterface;
use App\Domain\Mfa\Entities\MfaMethod;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Mockery;
use Tests\TestCase;

class AuthenticationTest extends TestCase
{
    use RefreshDatabase;

    // =========================================================================
    // REGISTRATION & LOGIN
    // =========================================================================

    public function test_user_can_register()
    {
        $response = $this->postJson('/api/v1/auth/register', [
            'name' => 'Sampad Singha',
            'email' => 'sampad@radixia.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
            'device_name' => 'Chrome',
            'marketing_opt_in' => true,
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure(['data' => ['user', 'token']]);

        $this->assertDatabaseHas('users', ['email' => 'sampad@radixia.com']);
    }

    public function test_user_can_login()
    {
        $user = User::factory()->create(['password' => Hash::make('password123')]);

        $response = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'password123',
            'device_name' => 'test-device'
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure(['data' => ['token']]);
    }

    public function test_user_cannot_login_with_invalid_credentials()
    {
        $user = User::factory()->create(['password' => Hash::make('correct-password')]);

        $response = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'wrong-password',
            'device_name' => 'test-device'
        ]);

        $response->assertStatus(401)
            ->assertJson(['message' => 'The provided credentials are incorrect.']);
    }

    public function test_user_can_logout()
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->postJson('/api/v1/auth/logout');

        $response->assertStatus(200)
            ->assertJsonPath('data.message', 'Logged out');
    }

    // =========================================================================
    // PASSWORD RESET
    // =========================================================================

    public function test_user_can_request_reset_link()
    {
        Notification::fake();
        User::factory()->create(['email' => 'forgot@radixia.com']);

        $response = $this->postJson('/api/v1/auth/forgot-password', [
            'email' => 'forgot@radixia.com'
        ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'We have emailed your password reset link.']);
    }

    public function test_user_can_reset_password_with_valid_token()
    {
        $user = User::factory()->create([
            'email' => 'reset@radixia.com',
            'password' => Hash::make('old-password')
        ]);

        $token = Password::createToken($user);

        $response = $this->postJson('/api/v1/auth/reset-password', [
            'email' => 'reset@radixia.com',
            'token' => $token,
            'password' => 'new-password',
            'password_confirmation' => 'new-password'
        ]);

        $response->assertStatus(200);
        $this->assertTrue(Hash::check('new-password', $user->fresh()->password));
    }

    // =========================================================================
    // SOCIAL LOGIN
    // =========================================================================

    public function test_social_callback_creates_user()
    {
        // 1. Mock the INTERFACE (Safe for readonly classes)
        $mockService = Mockery::mock(SocialAuthServiceInterface::class);

        $mockService->shouldReceive('handleProviderCallback')
            ->once()
            ->with('google', Mockery::any())
            ->andReturn([
                'user' => User::factory()->create(['email' => 'social@radixia.com']),
                'token' => 'mocked-token'
            ]);

        // 2. Swap the INTERFACE in the container
        $this->app->instance(SocialAuthServiceInterface::class, $mockService);

        $response = $this->postJson('/api/v1/auth/social/google/callback', [
            'code' => 'auth-code',
            'device_name' => 'test-device'
        ]);

        $response->assertStatus(200)
            ->assertJsonPath('data.user.email', 'social@radixia.com');
    }

    // =========================================================================
    // MFA (Multi-Factor Authentication)
    // =========================================================================

    public function test_user_can_enable_totp_mfa()
    {
        $user = User::factory()->create(['email' => 'john.doe@example.com']);

        $response = $this->actingAs($user)->postJson('/api/v1/auth/two-factor/enable', [
            'type' => 'totp'
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'type',
                'data' => [
                    'secret',
                    'qr_code_url',
                    'recovery_codes'
                ]
            ])
            ->assertJsonPath('type', 'totp')
            ->assertJsonPath('message', 'Setup initiated. Please confirm to activate.');

        $this->assertNotEmpty($response->json('data.secret'));
        $this->assertStringContainsString('otpauth://totp/Radixia', $response->json('data.qr_code_url'));
    }

    public function test_mfa_challenge_is_required_for_mfa_enabled_users()
    {
        $user = User::factory()->create(['password' => Hash::make('password')]);

        // Create MFA record (removed 'enabled_at' as per your schema fix)
        MfaMethod::factory()->create([
            'user_id' => $user->id,
            'type' => 'totp',
        ]);

        $response = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'password',
            'device_name' => 'Web'
        ]);

        // FIX 2: Expect 423 (Locked) instead of 200
        $response->assertStatus(423)
            ->assertJson([
                'message' => 'Two-factor authentication required.', // <--- Updated string
                'mfa_required' => true
            ]);

        $this->assertArrayNotHasKey('token', $response->json('data') ?? []);
    }

    public function test_confirm_sudo_password()
    {
        $user = User::factory()->create(['password' => Hash::make('password123')]);
        $token = $user->createToken('test');

        // FIX: Use correct validation fields from FormRequest
        $response = $this->withToken($token->plainTextToken)
            ->postJson('/api/v1/auth/confirm-sudo', [
                'type' => 'password',      // ← Required
                'value' => 'password123',  // ← Password field
            ]);

        $response->assertStatus(200);
        // Optional: Verify sudo_expires_at
        $this->assertNotNull($token->accessToken->fresh()->sudo_expires_at);
    }

}
