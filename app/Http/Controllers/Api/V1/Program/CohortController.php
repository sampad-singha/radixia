<?php

namespace App\Http\Controllers\Api\V1\Program;

use App\Domain\Programs\Exceptions\CohortNotEmptyException;
use App\Domain\Programs\Exceptions\CohortNotFoundException;
use App\Domain\Programs\Exceptions\RestrictedStatusException;
use App\Domain\Programs\Services\CohortServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Program\CreateCohortRequest;
use App\Http\Requests\Api\V1\Program\UpdateCohortRequest;
use Throwable;

class CohortController extends Controller
{
    public function __construct(
        private readonly CohortServiceInterface $cohortService
    )
    {}

    public function listCohortsByProgram(string $programId)
    {
        $cohorts = $this->cohortService->listCohortsByProgram($programId);

        return response()->json([
            'cohorts' => $cohorts,
        ]);
    }

    public function createCohort(CreateCohortRequest $request)
    {
        $data = $request->validated();

        $cohort = $this->cohortService->createCohort($data);

        return response()->json([
            'message' => 'Cohort created successfully.',
            'cohort' => $cohort,
        ]);
    }

    public function getCohortDetails(string $id)
    {
        $cohort = $this->cohortService->getCohortDetails($id);
        return response()->json([
            'cohort' => $cohort,
        ]);
    }

    public function updateCohort(string $cohortId, UpdateCohortRequest $request)
    {
        $data = $request->validated();

        $cohort = $this->cohortService->updateCohort($cohortId, $data);

        return response()->json([
            'message' => 'Cohort updated successfully.',
            'cohort' => $cohort,
        ]);
    }

    /**
     * @throws CohortNotEmptyException
     * @throws Throwable
     * @throws RestrictedStatusException
     */
    public function deleteCohort(string $id)
    {
        $this->cohortService->deleteCohort($id);

        return response()->json([
            'message' => 'Cohort and associated sessions successfully archived.'
        ]);
    }

    /**
     * Restore a soft-deleted cohort.
     * @throws Throwable
     */
    public function restoreCohort(string $id)
    {
        $this->cohortService->restoreCohort($id);

        return response()->json([
            'message' => 'Cohort and all history successfully restored.'
        ]);
    }
}
