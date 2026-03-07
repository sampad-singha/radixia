<?php

namespace App\Jobs;

use App\Application\Programs\Services\CohortSessionAttendanceService;
use App\Domain\Meetings\Services\MeetingCommandServiceInterface;
use App\Domain\Programs\Entities\CohortSession;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Throwable;

class CompleteCohortSessionJob implements ShouldQueue
{
    use Dispatchable, Queueable, SerializesModels;

    public int $tries = 3;
    public int $timeout = 120;

    /**
     * Create a new job instance.
     */
    public function __construct(public string $sessionId)
    {
        //
    }

    /**
     * Execute the job.
     * @throws Throwable
     */
    public function handle(
        CohortSessionAttendanceService $attendanceService,
        MeetingCommandServiceInterface $commandService
    ): void
    {

        $session = CohortSession::find($this->sessionId);

        if (!$session) {
            return;
        }

        try {
            if ($session->room_id) {
                $commandService->destroyByRoom($session->room_id);
            }
        } catch (Throwable $e) {
            Log::error("Room destroy failed for session {$session->id}: {$e->getMessage()}");
        }

        $attendanceService->calculateForSession($session->id);

        Cache::tags(["cohort_session_$session->id"])->flush();
    }
}
