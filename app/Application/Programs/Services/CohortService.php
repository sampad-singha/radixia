<?php

namespace App\Application\Programs\Services;

use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Enums\CohortStatus;
use App\Domain\Programs\Exceptions\CohortNotEmptyException;
use App\Domain\Programs\Exceptions\CohortNotFoundException;
use App\Domain\Programs\Exceptions\CohortUpdateException;
use App\Domain\Programs\Exceptions\FieldRestrictedException;
use App\Domain\Programs\Exceptions\ProgramNotFoundException;
use App\Domain\Programs\Exceptions\RestrictedStatusException;
use App\Domain\Programs\Repositories\CohortEnrollmentRepositoryInterface;
use App\Domain\Programs\Repositories\CohortRepositoryInterface;
use App\Domain\Programs\Repositories\ProgramRepositoryInterface;
use App\Domain\Programs\Services\CohortServiceInterface;
use Carbon\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Throwable;

readonly class CohortService implements CohortServiceInterface
{
    private const CACHE_PREFIX = 'cohort_';
    private const CACHE_TTL = 3600;

    public function __construct(
        private CohortRepositoryInterface $cohortRepository,
        private CohortEnrollmentRepositoryInterface $cohortEnrollmentRepository,
        private ProgramRepositoryInterface $programRepository
    ) {}

    /**
     * @throws CohortNotFoundException
     */
    public function findCohortById(string $id): Cohort
    {
        $cohort = $this->cohortRepository->findById($id);
        if(!$cohort) {
            throw new CohortNotFoundException();
        }
        return $cohort;
    }

    /**
     * @throws CohortNotFoundException
     */
    public function findCohortWithTrashed(string $id): Cohort
    {
        $cohort = $this->cohortRepository->findWithTrashed($id);
        if(!$cohort) {
            throw new CohortNotFoundException();
        }
        return $cohort;
    }

    public function listCohortsByProgram(string $programId): Collection
    {
        // Cache the list and tag it
        return Cache::tags(['cohorts_list', "program_$programId"])->remember(
            "cohorts_list_program_$programId",
            self::CACHE_TTL,
            fn() => $this->cohortRepository->findByProgram($programId)
        );
    }

    /**
     * @throws ProgramNotFoundException
     */
    public function createCohort(array $data): Cohort
    {
        $program = $this->programRepository->findById($data['program_id']);

        if (!$program) {
            throw new ProgramNotFoundException("Cannot create cohort: Program [{$data['program_id']}] not found.");
        }

        $cohortData = array_merge($data, [
            'status' => CohortStatus::SCHEDULED,
        ]);

        if(!isset($data['assigned_instructor_id']))
        {
            $cohortData['assigned_instructor_id'] = Auth::id();
        }

        $cohort = $this->cohortRepository->create($cohortData);

        $this->clearCohortCache($cohort->id);

        return $cohort;
    }

    /**
     * @throws CohortNotFoundException
     */
    public function getCohortDetails(string $id): Cohort
    {
        $cohort = $this->cohortRepository->findById($id);
        if (!$cohort) throw new CohortNotFoundException();

        return Cache::tags(["cohort_$id", "program_$cohort->program_id"])->remember(
            self::CACHE_PREFIX . $id,
            self::CACHE_TTL,
            fn() => $cohort->load(['program.modules.lessons'])
        );
    }


    /**
     * @throws RestrictedStatusException
     * @throws FieldRestrictedException
     * @throws CohortUpdateException
     */
    public function updateCohort(Cohort $cohort, array $data): Cohort
    {
        // 1. Prevent updates to Completed or Cancelled cohorts
        if (in_array($cohort->status, [CohortStatus::COMPLETED, CohortStatus::CANCELLED,])) {
            throw new RestrictedStatusException($cohort->status->value);
        }

        // 2. Prevent critical changes if students are already enrolled
        $activeAndReservedCount = $this->cohortEnrollmentRepository->countActiveAndReserved($cohort->id);

        if ($activeAndReservedCount > 0) {
            // Field Restrictions (Price/Program)
            foreach (['price', 'program_id'] as $field) {
                if (isset($data[$field]) && $data[$field] !== $cohort->{$field}) {
                    throw new FieldRestrictedException($field);
                }
            }

            // Capacity Restriction
            if (isset($data['capacity']) && $data['capacity'] < $activeAndReservedCount) {
                throw new CohortUpdateException("Capacity cannot be reduced below the $activeAndReservedCount currently enrolled/reserved students.");
            }
        }

        // 3. Date change logic
        if (isset($data['start_date']) &&
            $cohort->status === CohortStatus::ACTIVE &&
            Carbon::parse($data['start_date'])->ne(Carbon::parse($cohort->start_date))) {
            throw new CohortUpdateException();
        }

        if(!isset($data['assigned_instructor_id'])) {
            $data['assigned_instructor_id'] = $cohort->assigned_instructor_id;
        }

        $updatedCohort = $this->cohortRepository->update($cohort, $data);

        $this->clearCohortCache($cohort->id);

        return $updatedCohort;
    }

    /**
     * @throws RestrictedStatusException
     * @throws CohortNotEmptyException
     * @throws Throwable
     */
    public function deleteCohort(Cohort $cohort): bool
    {
        $occupiedSeats = $this->cohortEnrollmentRepository->countActiveAndReserved($cohort->id);
        if ($occupiedSeats > 0) {
            throw new CohortNotEmptyException($occupiedSeats);
        }

        if (in_array($cohort->status, [CohortStatus::ACTIVE, CohortStatus::COMPLETED,])) {
            throw new RestrictedStatusException($cohort->status->value);
        }

        $deleted = $this->cohortRepository->delete($cohort);

        $this->clearCohortCache($cohort->id);

        return $deleted;
    }

    /**
     * @throws Throwable
     */
    public function restoreCohort(Cohort $cohort): bool
    {
        $this->cohortRepository->restore($cohort);

        $this->clearCohortCache($cohort->id);

        return true;
    }

    private function clearCohortCache(string $cohortId): void
    {
        // Clear the specific cohort data
        Cache::tags(["cohort_$cohortId"])->flush();

        // Also clear the "list" tag if you have a listCohortsByProgram method cached
        Cache::tags(['cohorts_list'])->flush();
    }
}