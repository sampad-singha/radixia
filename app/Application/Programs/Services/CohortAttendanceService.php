<?php

namespace App\Application\Programs\Services;

use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Entities\CohortSession;
use App\Domain\Programs\Entities\CohortSessionAttendanceLog;
use App\Domain\Programs\Services\CohortAttendanceServiceInterface;
use App\Domain\Programs\Services\CohortSessionAttendanceServiceInterface;
use App\Models\User;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;

readonly class CohortAttendanceService implements CohortAttendanceServiceInterface
{
    const CACHE_TTL = 3600; // 1 hour in seconds

    public function __construct(
        private CohortSessionAttendanceServiceInterface $sessionAttendanceService
    ) {}
    public function getAttendanceForCohort(Cohort $cohort): Collection
    {
        $cacheKey = "cohort_attendance_sessions_$cohort->id";

        return Cache::tags([
            "cohort_$cohort->id",
            "cohort_attendance"
        ])->remember(
            $cacheKey,
            self::CACHE_TTL,
            function () use ($cohort) {

                return $cohort->sessions
                    ->map(function ($session) {

                        return [
                            'session_id' => $session->id,
                            'attendance' => $this->sessionAttendanceService
                                ->getAttendanceForSession($session),
                        ];

                    });

            }
        );
    }

    public function getAttendanceForStudent(Cohort $cohort, User $user): array
    {
        $userId = $user->id;
        $cacheKey = "cohort_student_attendance_{$cohort->id}_$userId";

        return Cache::tags([
            "cohort_$cohort->id",
            "student_$userId",
            "cohort_attendance"
        ])->remember(
            $cacheKey,
            self::CACHE_TTL,
            function () use ($cohort, $userId) {

                $logs = CohortSessionAttendanceLog::query()
                    ->where('user_id', $userId)
                    ->whereHas('cohortSession', fn ($q) =>
                    $q->where('cohort_id', $cohort->id)
                    )
                    ->get();

                $totalSessions = $cohort->sessions()->count();

                $attendedSessions = $logs
                    ->where('attended', true)
                    ->count();

                $attendancePercentage = $totalSessions
                    ? round(($attendedSessions / $totalSessions) * 100, 2)
                    : 0;

                $sessionDetails = $logs
                    ->map(function ($log) {
                        return [
                            'session_id' => $log->cohort_session_id,
                            'ratio_total' => $log->ratio_total,
                            'ratio_instructor' => $log->ratio_instructor,
                            'attended' => $log->attended,
                        ];
                    })
                    ->values()
                    ->toArray();

                return [
                    'user_id' => $userId,
                    'sessions_attended' => $attendedSessions,
                    'total_sessions' => $totalSessions,
                    'attendance_percentage' => $attendancePercentage,
                    'sessions' => $sessionDetails,
                ];
            }
        );
    }

    public function getStudentAttendanceSummaryForCohort(Cohort $cohort): array
    {
        $cacheKey = "cohort_student_summary_$cohort->id";

        return Cache::tags([
            "cohort_$cohort->id",
            "cohort_attendance"
        ])->remember(
            $cacheKey,
            self::CACHE_TTL,
            function () use ($cohort) {

                $logs = CohortSessionAttendanceLog::query()
                    ->whereHas('cohortSession', fn ($q) =>
                    $q->where('cohort_id', $cohort->id)
                    )
                    ->get();

                $totalSessions = $logs->groupBy('cohort_session_id')->count();

                $students = $logs
                    ->groupBy('user_id')
                    ->map(function ($studentLogs) use ($totalSessions) {

                        $attendedSessions = $studentLogs
                            ->where('attended', true)
                            ->count();

                        return [
                            'user_id' => $studentLogs->first()->user_id,
                            'sessions_attended' => $attendedSessions,
                            'total_sessions' => $totalSessions,
                            'attendance_ratio' => $totalSessions
                                ? $attendedSessions / $totalSessions
                                : 0,
                        ];
                    })
                    ->values()
                    ->toArray();

                return [
                    'total_sessions' => $totalSessions,
                    'students' => $students,
                ];
            }
        );
    }

    public function getCohortAttendanceSummary(Cohort $cohort): array
    {
        $cacheKey = "cohort_attendance_summary_$cohort->id";

        return Cache::tags([
            "cohort_$cohort->id",
            "cohort_attendance"
        ])->remember(
            $cacheKey,
            self::CACHE_TTL,
            function () use ($cohort) {

                $totalSessions = $cohort->sessions()->count();

                $students = $cohort->enrollments()
                    ->where('status', 'active')
                    ->pluck('user_id');

                $totalStudents = $students->count();

                $logs = CohortSessionAttendanceLog::query()
                    ->whereIn('user_id', $students)
                    ->whereHas('cohortSession', fn ($q) =>
                    $q->where('cohort_id', $cohort->id)
                    )
                    ->get()
                    ->groupBy('user_id');

                $attendancePerStudent = $students->map(function ($userId) use ($logs, $totalSessions) {

                    $studentLogs = $logs->get($userId, collect());

                    $attendedSessions = $studentLogs
                        ->where('attended', true)
                        ->count();

                    $attendanceRatio = $totalSessions
                        ? $attendedSessions / $totalSessions
                        : 0;

                    return [
                        'user_id' => $userId,
                        'sessions_attended' => $attendedSessions,
                        'attendance_ratio' => $attendanceRatio,
                    ];
                });

                $averageAttendance = $attendancePerStudent->avg('attendance_ratio');

                $studentsBelowThreshold = $attendancePerStudent
                    ->where('attendance_ratio', '<', 0.5)
                    ->count();

                return [
                    'cohort_id' => $cohort->id,
                    'total_students' => $totalStudents,
                    'total_sessions' => $totalSessions,
                    'average_attendance_ratio' => round($averageAttendance ?? 0, 4),
                    'students_below_threshold' => $studentsBelowThreshold,
                ];
            }
        );
    }

    public function getSessionAttendanceSummary(CohortSession $session): array
    {
        $cacheKey = "session_attendance_summary_{$session->id}";

        return Cache::tags([
            "cohort_{$session->cohort_id}",
            "session_{$session->id}",
            "cohort_attendance"
        ])->remember(
            $cacheKey,
            CohortSessionAttendanceService::CACHE_TTL,
            function () use ($session) {

                $studentIds = $session->cohort
                    ->enrollments()
                    ->where('status', 'active')
                    ->pluck('user_id');

                $totalStudents = $studentIds->count();

                $logs = CohortSessionAttendanceLog::query()
                    ->where('cohort_session_id', $session->id)
                    ->whereIn('user_id', $studentIds)   // ensure only enrolled students
                    ->get();

                $attendedStudents = $logs
                    ->where('attended', true)
                    ->count();

                $attendanceRatio = $totalStudents
                    ? $attendedStudents / $totalStudents
                    : 0;

                $averageStudentPresence = $logs->avg('ratio_total') ?? 0;

                $averageInstructorOverlap = $logs->avg('ratio_instructor') ?? 0;

                return [
                    'session_id' => $session->id,
                    'cohort_id' => $session->cohort_id,
                    'total_students' => $totalStudents,
                    'students_attended' => $attendedStudents,
                    'attendance_ratio' => round($attendanceRatio, 4),
                    'average_student_presence_ratio' => round($averageStudentPresence, 4),
                    'average_instructor_overlap_ratio' => round($averageInstructorOverlap, 4),
                ];
            }
        );
    }
}
