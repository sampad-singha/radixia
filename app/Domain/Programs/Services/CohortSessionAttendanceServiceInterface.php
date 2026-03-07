<?php

namespace App\Domain\Programs\Services;

use App\Domain\Programs\Entities\CohortSession;

interface CohortSessionAttendanceServiceInterface
{
    public function calculateForSession(string $cohortSessionId): void;
    public function getAttendanceForSession(CohortSession $cohortSession): array;
}