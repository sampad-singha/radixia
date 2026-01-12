<?php

namespace App\Http\Controllers\Api\V1\User;

use App\Domain\Users\Services\UserProfileServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\User\UpdateUserProfileRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class UserProfileController extends Controller
{
    public function __construct(
        private readonly UserProfileServiceInterface $service
    ) {}

    public function show(Request $request): JsonResponse
    {
        $profile = $this->service->getProfile($request->user());

        return response()->json([
            'data' => $profile
        ]);
    }

    public function update(UpdateUserProfileRequest $request): JsonResponse
    {
        $profile = $this->service->updateProfile(
            $request->user(),
            $request->validated()
        );

        return response()->json([
            'message' => 'Profile updated successfully.',
            'data' => $profile
        ]);
    }
}
