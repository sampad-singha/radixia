<?php

namespace App\Domain\Programs\Services;

use App\Domain\Programs\Entities\Cohort;
use Illuminate\Support\Collection;

interface CohortServiceInterface
{
    public function listCohortsByProgram(string $programId): Collection;
    public function createCohort(array $data): Cohort;
    public function getCohortDetails(string $id): Cohort;
    public function updateCohort(string $cohortId, array $data): Cohort;
}