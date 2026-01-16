<?php

namespace App\Http\Controllers\Api\V1\Instructor;

use App\Domain\Instructors\Services\InstructorProfileServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Instructor\StoreInstructorProfileRequest;
use App\Http\Requests\Api\V1\Instructor\UpdateInstructorProfileRequest;
use App\Http\Resources\Api\V1\Instructor\InstructorProfileResource;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class InstructorProfileController extends Controller
{
    public function __construct(
        private readonly InstructorProfileServiceInterface $service
    ) {}

    public function show(Request $request): JsonResponse
    {
        $profile = $this->service->getProfile($request->user());

        return response()->json([
            'data' => new InstructorProfileResource($profile),
        ]);
    }

    public function store(StoreInstructorProfileRequest $request): JsonResponse
    {
        $profile = $this->service->createProfile(
            $request->user(),
            $request->validated()
        );

        return response()->json([
            'message' => 'Instructor profile created successfully.',
            'data' => new InstructorProfileResource($profile),
        ], 201);
    }

    public function update(UpdateInstructorProfileRequest $request): JsonResponse
    {
        $profile = $this->service->updateProfile(
            $request->user(),
            $request->validated()
        );

        return response()->json([
            'message' => 'Instructor profile updated successfully.',
            'data' => new InstructorProfileResource($profile),
        ]);
    }
}
