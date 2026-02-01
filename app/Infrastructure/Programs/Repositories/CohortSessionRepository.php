<?php

namespace App\Infrastructure\Programs\Repositories;

use App\Domain\Programs\Entities\CohortSession;
use App\Domain\Programs\Repositories\CohortSessionRepositoryInterface;
use Illuminate\Support\Collection;

class CohortSessionRepository implements CohortSessionRepositoryInterface
{
    public function create(array $data): CohortSession
    {
        return CohortSession::create($data);
    }


    public function update(CohortSession $session, array $data): CohortSession
    {
        $session->update($data);
        return $session->fresh();
    }


    public function delete(CohortSession $session): void
    {
        $session->delete();
    }

    public function restore(CohortSession $session): void
    {
        $session->restore();
    }


    public function findById(string $id): ?CohortSession
    {
        return CohortSession::query()->find($id);
    }


    public function findByCohort(string $cohortId): Collection
    {
        return CohortSession::query()
            ->where('cohort_id', $cohortId)
            ->orderBy('starts_at')
            ->get();
    }
}