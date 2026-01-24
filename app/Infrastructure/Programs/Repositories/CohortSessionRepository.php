<?php

namespace App\Infrastructure\Programs\Repositories;

use App\Domain\Programs\Entities\CohortSession;
use App\Domain\Programs\Repositories\CohortSessionRepositoryInterface;
use Carbon\Carbon;
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


    public function hasOverlap(
        string $cohortId,
        Carbon $startsAt,
        Carbon $endsAt,
        ?string $ignoreSessionId = null
    ): bool {
        return CohortSession::query()
            ->where('cohort_id', $cohortId)
            ->when($ignoreSessionId, fn ($q) =>
            $q->where('id', '!=', $ignoreSessionId)
            )
            ->where(function ($q) use ($startsAt, $endsAt) {
                $q->whereBetween('starts_at', [$startsAt, $endsAt])
                    ->orWhereBetween('ends_at', [$startsAt, $endsAt])
                    ->orWhere(function ($q) use ($startsAt, $endsAt) {
                        $q->where('starts_at', '<=', $startsAt)
                            ->where('ends_at', '>=', $endsAt);
                    });
            })
            ->exists();
    }
}