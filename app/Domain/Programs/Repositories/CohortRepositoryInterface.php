<?php

namespace App\Domain\Programs\Repositories;

use App\Domain\Programs\Entities\Cohort;
use Illuminate\Support\Collection;

interface CohortRepositoryInterface
{
    public function create(array $data): Cohort;

    public function update(Cohort $cohort, array $data): Cohort;

    public function delete(Cohort $cohort): bool;

    public function restore(Cohort $cohort): bool;

    public function findById(string $id): ?Cohort;

    public function findByProgram(string $programId): Collection;

    public function findActiveByProgram(string $programId): Collection;

    public function isUserEnrolled(string $cohortId, string $userId): bool;

    public function findWithTrashed(string $id): ?Cohort;
}