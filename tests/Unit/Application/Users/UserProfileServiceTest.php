<?php

namespace Tests\Unit\Application\Users;

use App\Application\Users\Services\UserProfileService;
use App\Domain\Users\Entities\UserProfile;
use App\Domain\Users\Repositories\UserProfileRepositoryInterface;
use App\Models\User;
use Illuminate\Support\Str;
use Mockery;
use Tests\TestCase;

class UserProfileServiceTest extends TestCase
{
    private UserProfileRepositoryInterface|Mockery\MockInterface $repo;
    private UserProfileService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->repo = Mockery::mock(UserProfileRepositoryInterface::class);
        $this->service = new UserProfileService($this->repo);
    }

    public function test_get_profile_returns_profile()
    {
        $user = User::factory()->create();

        // Raw mock data for Entity (no factory needed)
        $profileData = [
            'id' => Str::uuid()->toString(),
            'user_id' => $user->id,
            'bio' => 'Test bio',
            'phone' => '1234567890',
            'country' => 'BD',
        ];

        $profile = new UserProfile();
        foreach ($profileData as $key => $value) {
            $profile->{$key} = $value;
        }

        $this->repo->shouldReceive('findByUser')->with($user)->once()->andReturn($profile);

        $result = $this->service->getProfile($user);

        $this->assertSame($profile, $result);
    }

}
