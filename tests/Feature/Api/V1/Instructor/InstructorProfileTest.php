<?php

namespace Tests\Feature\Api\V1\Instructor;

use App\Domain\Instructors\Entities\InstructorProfile;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class InstructorProfileTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_create_instructor_profile()
    {
        $user = User::factory()->create();

        $data = [
            'headline' => 'Expert Laravel Developer',
            'bio' => 'Teaching code for 10 years.',
            'intro_video_url' => 'https://vimeo.com/123456',
        ];

        $response = $this->actingAs($user)->postJson('/api/v1/instructor/profile', $data);

        $response->assertStatus(201)
            ->assertJsonPath('data.headline', 'Expert Laravel Developer');

        $this->assertDatabaseHas('instructor_profiles', [
            'user_id' => $user->id,
            'headline' => 'Expert Laravel Developer',
        ]);
    }

    public function test_user_can_view_own_instructor_profile()
    {
        $user = User::factory()->create();
        InstructorProfile::create([
            'user_id' => $user->id,
            'headline' => 'Existing Headline',
            'bio' => 'Bio',
            'is_verified' => false
        ]);

        $response = $this->actingAs($user)->getJson('/api/v1/instructor/profile');

        $response->assertStatus(200)
            ->assertJsonPath('data.headline', 'Existing Headline');
    }

    public function test_user_can_update_instructor_profile()
    {
        $user = User::factory()->create();
        InstructorProfile::create([
            'user_id' => $user->id,
            'headline' => 'Old Headline',
            'bio' => 'Old Bio',
        ]);

        $data = ['headline' => 'New Headline'];

        $response = $this->actingAs($user)->putJson('/api/v1/instructor/profile', $data);

        $response->assertStatus(200)
            ->assertJsonPath('data.headline', 'New Headline');
    }
}
