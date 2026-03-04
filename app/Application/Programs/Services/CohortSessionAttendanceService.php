<?php

namespace App\Application\Programs\Services;

use App\Domain\Programs\Entities\CohortSession;
use App\Domain\Programs\Entities\CohortSessionAttendanceLog;
use App\Domain\Programs\Entities\CohortSessionParticipantInterval;
use App\Domain\Programs\Entities\CohortSessionStat;
use App\Domain\Programs\Services\CohortSessionAttendanceServiceInterface;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Throwable;

class CohortSessionAttendanceService implements CohortSessionAttendanceServiceInterface
{
    const CACHE_TTL = 3600; // 1 hour in seconds

    /**
     * @throws Throwable
     */
    public function calculateForSession(string $cohortSessionId): void
    {
        DB::transaction(function () use ($cohortSessionId) {

            $stats = CohortSessionStat::where('cohort_session_id', $cohortSessionId)
                ->select('id', 'finalized')
                ->first();

            if ($stats && $stats->finalized) {
                return;
            }

            $cohortSession = CohortSession::findOrFail($cohortSessionId);

            $this->closeOpenIntervals($cohortSessionId);

            [$totalMeetingMs, $instructorActiveMs, $mergedInstructorIntervals] =
                $this->computeSessionStats($cohortSessionId);

            CohortSessionStat::updateOrCreate(
                ['cohort_session_id' => $cohortSessionId],
                [
                    'total_meeting_ms'     => $totalMeetingMs,
                    'instructor_active_ms' => $instructorActiveMs,
                    'finalized'            => true,
                ]
            );

            $this->computeStudentAttendance(
                $cohortSessionId,
                $totalMeetingMs,
                $instructorActiveMs,
                $mergedInstructorIntervals
            );

            Cache::tags([
                "cohort_{$cohortSession->cohort_id}",
                "cohort_attendance"
            ])->flush();
        });
    }

    public function getAttendanceForSession(CohortSession $cohortSession): array
    {
        $cacheKey = "session_attendance_{$cohortSession->id}";

        return Cache::tags([
            "cohort_session_{$cohortSession->id}",
            "session_attendance"
        ])->remember(
            $cacheKey,
            self::CACHE_TTL,
            fn () => CohortSessionAttendanceLog::where('cohort_session_id', $cohortSession->id)
                ->with('user')
                ->get()
                ->map(function ($log) {
                    return [
                        'user_id' => $log->user_id,
                        'name' => $log->user?->name,
                        'student_active_ms' => $log->student_active_ms,
                        'student_instructor_overlap_ms' => $log->student_instructor_overlap_ms,
                        'ratio_total' => $log->ratio_total,
                        'ratio_instructor' => $log->ratio_instructor,
                        'attended' => $log->attended,
                    ];
                })
                ->values()
                ->toArray()
        );
    }

    private function closeOpenIntervals(string $cohortSessionId): void
    {
        $now = now()->valueOf(); // ms

        CohortSessionParticipantInterval::where('cohort_session_id', $cohortSessionId)
            ->whereNull('left_at')
            ->get()
            ->each(function ($interval) use ($now) {
                $interval->left_at = $now;
                $interval->duration_ms = $now - $interval->joined_at;
                $interval->save();
            });
    }

    private function computeSessionStats(string $cohortSessionId): array
    {
        $intervals = CohortSessionParticipantInterval::where('cohort_session_id', $cohortSessionId)
            ->where('is_moderator', true)
            ->whereNotNull('user_id')
            ->get(['joined_at', 'left_at'])
            ->toArray();

        $mergedInstructorIntervals = $this->mergeIntervals($intervals);

        $instructorActiveMs = collect($mergedInstructorIntervals)
            ->sum(fn ($i) => $i['end'] - $i['start']);

        $minJoined = CohortSessionParticipantInterval::where('cohort_session_id', $cohortSessionId)
            ->min('joined_at');

        $maxLeft = CohortSessionParticipantInterval::where('cohort_session_id', $cohortSessionId)
            ->max('left_at');

        $totalMeetingMs = ($minJoined && $maxLeft)
            ? $maxLeft - $minJoined
            : 0;

        return [$totalMeetingMs, $instructorActiveMs, $mergedInstructorIntervals];
    }

    private function computeStudentAttendance(
        string $cohortSessionId,
        int $totalMeetingMs,
        int $instructorActiveMs,
        array $mergedInstructorIntervals
    ): void {

        $intervals = CohortSessionParticipantInterval::where('cohort_session_id', $cohortSessionId)
            ->whereNotNull('user_id')
            ->where('is_moderator', false)
            ->get(['user_id','joined_at','left_at']);

        $intervalsByUser = $intervals->groupBy('user_id');

        foreach ($intervalsByUser as $userId => $userIntervals) {

            $intervalArray = $userIntervals
                ->map(fn ($i) => [
                    'joined_at' => $i->joined_at,
                    'left_at' => $i->left_at
                ])
                ->toArray();

            $mergedStudentIntervals = $this->mergeIntervals($intervalArray);

            $studentActiveMs = collect($mergedStudentIntervals)
                ->sum(fn ($i) => $i['end'] - $i['start']);

            $studentInstructorOverlapMs = $this->computeOverlap(
                $mergedStudentIntervals,
                $mergedInstructorIntervals
            );

            $ratioTotal = $totalMeetingMs > 0
                ? $studentActiveMs / $totalMeetingMs
                : 0;

            $ratioInstructor = $instructorActiveMs > 0
                ? $studentInstructorOverlapMs / $instructorActiveMs
                : 0;

            $attended = ($ratioTotal >= 0.5) || ($ratioInstructor >= 0.5);

            CohortSessionAttendanceLog::updateOrCreate(
                [
                    'cohort_session_id' => $cohortSessionId,
                    'user_id' => $userId,
                ],
                [
                    'student_active_ms' => $studentActiveMs,
                    'student_instructor_overlap_ms' => $studentInstructorOverlapMs,
                    'ratio_total' => $ratioTotal,
                    'ratio_instructor' => $ratioInstructor,
                    'attended' => $attended,
                ]
            );
        }
    }

    private function mergeIntervals(array $intervals): array
    {
        if (empty($intervals)) {
            return [];
        }

        usort($intervals, fn ($a, $b) => $a['joined_at'] <=> $b['joined_at']);

        $merged = [];
        foreach ($intervals as $interval) {
            $start = $interval['joined_at'];
            $end   = $interval['left_at'];

            if (!$end) {
                continue;
            }

            if (empty($merged) || $start > $merged[count($merged) - 1]['end']) {
                $merged[] = ['start' => $start, 'end' => $end];
            } else {
                $merged[count($merged) - 1]['end'] =
                    max($merged[count($merged) - 1]['end'], $end);
            }
        }

        return $merged;
    }

    private function computeOverlap(array $student, array $instructor): int
    {
        $i = 0;
        $j = 0;

        $overlap = 0;

        while ($i < count($student) && $j < count($instructor)) {

            $s = $student[$i];
            $t = $instructor[$j];

            $start = max($s['start'], $t['start']);
            $end   = min($s['end'], $t['end']);

            if ($end > $start) {
                $overlap += ($end - $start);
            }

            if ($s['end'] < $t['end']) {
                $i++;
            } else {
                $j++;
            }
        }

        return $overlap;
    }
}
