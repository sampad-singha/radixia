<?php

namespace App\Domain\Programs\Services;

use App\Domain\Programs\Entities\Cohort;

interface CohortServiceInterface
{
    public function create(array $data): Cohort;


    public function update(string $cohortId, array $data): Cohort;


    public function open(string $cohortId): Cohort;


    public function close(string $cohortId): Cohort;
}