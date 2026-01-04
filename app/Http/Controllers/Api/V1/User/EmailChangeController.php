<?php

namespace App\Http\Controllers\Api\V1\User;

use App\Domain\Users\Services\EmailChangeServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\User\RequestEmailChangeRequest;
use App\Http\Requests\Api\V1\User\VerifyEmailChangeRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class EmailChangeController extends Controller
{
    public function __construct(
        private readonly EmailChangeServiceInterface $emailChangeService
    ) {}

    public function store(RequestEmailChangeRequest $request): JsonResponse
    {
        $this->emailChangeService->requestChange($request->user(), $request->validated('email'));

        return response()->json([
            'message' => 'Verification code sent to the new email address.'
        ]);
    }

    public function verify(VerifyEmailChangeRequest $request): JsonResponse
    {
        $this->emailChangeService->verifyChange($request->user(), $request->validated('code'));

        return response()->json([
            'message' => 'Email address updated successfully.'
        ]);
    }
}
