<?php

namespace App\Http\Controllers\Api\V1\Program;

use App\Domain\Programs\Services\CohortSessionServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Program\ScheduleSessionRequest;
use App\Http\Requests\Api\V1\Program\UpdateSessionRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class CohortSessionController extends Controller
{
    public function __construct(
        private readonly CohortSessionServiceInterface $sessionService
    ) {}

    public function show(string $id)
    {
        $session = $this->sessionService->getById($id);

        return response()->json([
            'data' => $session,
        ]);
    }

    public function store(ScheduleSessionRequest $request)
    {
        $session = $this->sessionService->scheduleSession(
            $request->validated()
        );

        return response()->json([
            'data' => $session,
        ], 201);
    }

    public function update(UpdateSessionRequest $request, string $id)
    {
        $session = $this->sessionService->getById($id);

        $updated = $this->sessionService->updateSession(
            $session,
            $request->validated()
        );

        return response()->json([
            'data' => $updated,
        ]);
    }

    public function destroy(string $id)
    {
        $session = $this->sessionService->getById($id);

        $this->sessionService->deleteSession($session);

        return response()->json([
            'message' => 'Session deleted successfully.',
        ]);
    }

    public function restore(string $id)
    {
        $session = $this->sessionService->getById($id);

        $restored = $this->sessionService->restoreSession($session);

        return response()->json([
            'data' => $restored,
        ]);
    }

    public function join(string $id)
    {
        $session = $this->sessionService->getById($id);

        $joinUrl = $this->sessionService->getJoinLink(
            $session,
            Auth::user()
        );

        return response()->json([
            'data' => [
                'join_url' => $joinUrl,
            ],
        ]);
    }

    public function complete(string $id)
    {
        $session = $this->sessionService->getById($id);

        $completed = $this->sessionService->markSessionCompleted($session);

        return response()->json([
            'data' => $completed,
        ]);
    }

    public function cancel(string $id, Request $request)
    {
        $session = $this->sessionService->getById($id);

        $cancelled = $this->sessionService->cancelSession(
            $session,
            $request->input('cancellation_reason')
        );

        return response()->json([
            'data' => $cancelled,
        ]);
    }
}
