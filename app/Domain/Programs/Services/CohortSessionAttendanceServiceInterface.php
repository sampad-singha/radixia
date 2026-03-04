<?php

namespace App\Domain\Programs\Services;

interface CohortSessionAttendanceServiceInterface
{
    public function calculateForSession(string $cohortSessionId): void;
}