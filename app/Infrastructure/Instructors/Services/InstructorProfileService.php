<?php

namespace App\Infrastructure\Instructors\Services;

use App\Domain\Instructors\Entities\InstructorProfile;
use App\Domain\Instructors\Exceptions\InstructorProfileAlreadyExistsException;
use App\Domain\Instructors\Exceptions\InstructorProfileNotFoundException;
use App\Domain\Instructors\Repositories\InstructorProfileRepositoryInterface;
use App\Domain\Instructors\Services\InstructorProfileServiceInterface;
use App\Models\User;
use Illuminate\Support\Arr;

readonly class InstructorProfileService implements InstructorProfileServiceInterface
{
    public function __construct(
        private InstructorProfileRepositoryInterface $repository
    ) {}

    public function getProfile(User $user): InstructorProfile
    {
        $profile = $this->repository->findByUserId($user->id);

        if (! $profile) {
            throw new InstructorProfileNotFoundException();
        }

        return $profile;
    }

    public function createProfile(User $user, array $data): InstructorProfile
    {
        if ($this->repository->findByUserId($user->id)) {
            throw new InstructorProfileAlreadyExistsException();
        }

        return $this->repository->create($user, $data);
    }

    public function updateProfile(User $user, array $data): InstructorProfile
    {
        $profile = $this->repository->findByUserId($user->id);

        if (! $profile) {
            throw new InstructorProfileNotFoundException();
        }

        $safeData = Arr::only($data, [
            'headline',
            'bio',
            'intro_video_url'
        ]);

        return $this->repository->update($profile, $safeData);
    }
}
