<?php

namespace App\Infrastructure\Programs\Repositories;

use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Enums\CohortStatus;
use App\Domain\Programs\Repositories\CohortRepositoryInterface;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Throwable;

class CohortRepository implements CohortRepositoryInterface
{
    public function create(array $data): Cohort
    {
        return Cohort::create($data);
    }


    public function update(Cohort $cohort, array $data): Cohort
    {
        $cohort->update($data);
        return $cohort->fresh();
    }

    /**
     * @throws Throwable
     */
    public function delete(Cohort $cohort): bool
    {
        return DB::transaction(function () use ($cohort) {
            // 1. Soft delete children first
            $cohort->sessions()->delete();
            $cohort->enrollments()->delete();

            // 2. Soft delete the parent
            return $cohort->delete();
        });
    }

    /**
     * @throws Throwable
     */
    public function restore(string $id): bool
    {
        return DB::transaction(function () use ($id) {
            // We must use withTrashed() to find the record
            $cohort = Cohort::withTrashed()->findOrFail($id);

            // 1. Restore the parent
            $restored = $cohort->restore();

            if ($restored) {
                // 2. Restore children
                /** @var HasMany $sessions */
                $cohort->sessions()->withTrashed()->get()->each->restore();
                $cohort->enrollments()->withTrashed()->get()->each->restore();
            }

            return $restored;
        });
    }


    public function findById(string $id): ?Cohort
    {
        return Cohort::query()->find($id);
    }

    public function findOrFail(string $id): Cohort
    {
        return Cohort::query()->findOrFail($id);
    }


    public function findByProgram(string $programId): Collection
    {
        return Cohort::query()
            ->where('program_id', $programId)
            ->whereNot('status', CohortStatus::CANCELLED)
            ->orderBy('start_date', 'desc')
            ->get();
    }


    public function findActiveByProgram(string $programId): Collection
    {
        return Cohort::query()
            ->where('program_id', $programId)
            ->whereIn('status', [CohortStatus::SCHEDULED, CohortStatus::ACTIVE])
            ->orderBy('start_date', 'desc')
            ->get();
    }

    public function isUserEnrolled(string $cohortId, string $userId): bool
    {
        return DB::table('cohort_enrollments')
            ->where('cohort_id', $cohortId)
            ->where('user_id', $userId)
            ->where('status', CohortStatus::ACTIVE)
            ->exists();
    }
}