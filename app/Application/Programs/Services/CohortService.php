<?php

namespace App\Application\Programs\Services;

use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Repositories\CohortRepositoryInterface;
use App\Domain\Programs\Repositories\ProgramRepositoryInterface;
use App\Domain\Programs\Services\CohortServiceInterface;

readonly class CohortService implements CohortServiceInterface
{
    public function __construct(
        private CohortRepositoryInterface  $cohortRepository,
        private ProgramRepositoryInterface $programRepository
    ) {}


    public function create(array $data): Cohort
    {
        $this->programRepository->findOrFail($data['program_id']);


        $data['sold_seats'] = 0;
        $data['status'] = 'draft';


        return $this->cohortRepository->create($data);
    }


    public function update(string $cohortId, array $data): Cohort
    {
        $cohort = $this->cohortRepository->findOrFail($cohortId);


        return $this->cohortRepository->update($cohort, $data);
    }


    public function open(string $cohortId): Cohort
    {
        $cohort = $this->cohortRepository->findOrFail($cohortId);


        return $this->cohortRepository->update($cohort, [
            'status' => 'open',
        ]);
    }


    public function close(string $cohortId): Cohort
    {
        $cohort = $this->cohortRepository->findOrFail($cohortId);


        return $this->cohortRepository->update($cohort, [
            'status' => 'closed',
        ]);
    }
}