<?php

namespace App\Infrastructure\Programs\Repositories;

use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Repositories\CohortRepositoryInterface;
use Illuminate\Support\Collection;

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
            ->orderBy('start_date')
            ->get();
    }


    public function findActiveByProgram(string $programId): Collection
    {
        return Cohort::query()
            ->where('program_id', $programId)
            ->whereIn('status', ['scheduled', 'active'])
            ->orderBy('start_date')
            ->get();
    }
}