<?php

namespace App\Domain\Programs\Repositories;

use App\Domain\Programs\Entities\CohortSession;
use Carbon\Carbon;
use Illuminate\Support\Collection;

interface CohortSessionRepositoryInterface
{
    public function create(array $data): CohortSession;


    public function update(CohortSession $session, array $data): CohortSession;


    public function delete(CohortSession $session): void;


    public function findById(string $id): ?CohortSession;


    public function findByCohort(string $cohortId): Collection;


    /**
     * Used to prevent overlapping sessions within the same cohort.
     */
    public function hasOverlap(
        string $cohortId,
        Carbon $startsAt,
        Carbon $endsAt,
        ?string $ignoreSessionId = null
    ): bool;
}