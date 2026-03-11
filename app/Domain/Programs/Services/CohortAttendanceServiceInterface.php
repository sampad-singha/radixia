<?php

namespace App\Domain\Programs\Services;

use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Entities\CohortSession;
use App\Models\User;
use Illuminate\Support\Collection;

interface CohortAttendanceServiceInterface
{
    public function getAttendanceForCohort(Cohort $cohort): Collection;
    public function getAttendanceForStudent(Cohort $cohort, User $user): array;
    public function getStudentAttendanceSummaryForCohort(Cohort $cohort): array;
    public function getCohortAttendanceSummary(Cohort $cohort): array;
    public function getSessionAttendanceSummary(CohortSession $session): array;
}
