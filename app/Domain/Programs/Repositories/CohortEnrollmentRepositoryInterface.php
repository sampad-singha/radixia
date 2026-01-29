<?php

namespace App\Domain\Programs\Repositories;

use App\Domain\Programs\Entities\CohortEnrollment;

interface CohortEnrollmentRepositoryInterface
{
    public function findById(string $id): ?CohortEnrollment;

    public function findPending(string $userId, string $cohortId): ?CohortEnrollment;

    public function create(array $data): CohortEnrollment;

    public function countActiveAndReserved(string $cohortId): int;

    public function updateStatus(string $id, string $status, array $extraData = []): CohortEnrollment;

    public function findByUserAndCohort(string $userId, string $cohortId): ?CohortEnrollment;
}