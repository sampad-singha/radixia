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
}