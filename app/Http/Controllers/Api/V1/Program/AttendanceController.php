<?php

namespace App\Http\Controllers\Api\V1\Program;

use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Entities\CohortSession;
use App\Domain\Programs\Services\CohortAttendanceServiceInterface;
use App\Domain\Programs\Services\CohortSessionAttendanceServiceInterface;
use App\Http\Controllers\Controller;
use App\Models\User;

class AttendanceController extends Controller
{
    public function __construct(
        private readonly CohortAttendanceServiceInterface        $cohortAttendanceService,
        private readonly CohortSessionAttendanceServiceInterface $sessionAttendanceService
    )
    {
    }

    /**
     * Attendance for a single session
     */
    public function getSessionAttendance(CohortSession $session)
    {
        $this->authorize('viewAttendance', $session->cohort);

        $attendance = $this->sessionAttendanceService
            ->getAttendanceForSession($session);

        return response()->json([
            'session_id' => $session->id,
            'attendance' => $attendance
        ]);
    }

    /**
     * Attendance for all sessions in a cohort
     */
    public function getCohortAttendance(Cohort $cohort)
    {
        $this->authorize('viewAttendance', $cohort);
        $attendance = $this->cohortAttendanceService
            ->getAttendanceForCohort($cohort);

        return response()->json([
            'cohort_id' => $cohort->id,
            'sessions' => $attendance
        ]);
    }

    /**
     * Attendance for a single student in a cohort
     */
    public function getStudentAttendance(Cohort $cohort, User $user)
    {
        $this->authorize('viewStudentAttendance', [$cohort, $user]);

        $attendance = $this->cohortAttendanceService
            ->getAttendanceForStudent($cohort, $user);

        return response()->json($attendance);
    }

    /**
     * Cohort attendance summary
     */
    public function getCohortSummary(Cohort $cohort)
    {
        $this->authorize('viewAttendance', $cohort);

        $summary = $this->cohortAttendanceService
            ->getCohortAttendanceSummary($cohort);


        return response()->json($summary);
    }

    /**
     * Session attendance summary
     */
    public function getSessionSummary(CohortSession $session)
    {
        $cohort = $session->cohort;
        $this->authorize('viewAttendance', $cohort);

        $summary = $this->cohortAttendanceService
            ->getSessionAttendanceSummary($session);

        return response()->json($summary);
    }
}
