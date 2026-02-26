<?php

namespace App\Domain\Programs\Services;

use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Entities\CohortSession;
use Illuminate\Support\Collection;

interface CohortServiceInterface
{
    public function listCohortsByProgram(string $programId): Collection;
    public function createCohort(array $data): Cohort;
    public function getCohortDetails(string $id): Cohort;
    public function updateCohort(Cohort $cohort, array $data): Cohort;
    public function deleteCohort(Cohort $cohort): bool;
    public function restoreCohort(Cohort $cohort): bool;
    public function findCohortById(string $id): Cohort;
    public function findCohortWithTrashed(string $id): Cohort;
}