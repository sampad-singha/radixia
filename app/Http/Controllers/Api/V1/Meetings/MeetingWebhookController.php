<?php

namespace App\Http\Controllers\Api\V1\Meetings;

use App\Http\Controllers\Controller;
use App\Jobs\ProcessMeetingWebhook;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class MeetingWebhookController extends Controller
{
    public function __construct(
        //
    ) {}

    public function handleMeetWebhook(Request $request): JsonResponse
    {
        ProcessMeetingWebhook::dispatch(
            payload: $request->all()
        );

        return response()->json(['status' => 'ok'], 200);
    }
}
