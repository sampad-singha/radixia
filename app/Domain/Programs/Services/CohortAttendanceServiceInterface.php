<?php

namespace App\Domain\Programs\Services;

use App\Domain\Programs\Entities\Cohort;
use Illuminate\Support\Collection;

interface CohortAttendanceServiceInterface
{
    public function getAttendanceForCohort(Cohort $cohort): Collection;
    public function getAttendanceForStudent(Cohort $cohort, string $userId): array;
    public function getStudentAttendanceSummaryForCohort(Cohort $cohort): array;
    public function getCohortAttendanceSummary(Cohort $cohort): array;
}