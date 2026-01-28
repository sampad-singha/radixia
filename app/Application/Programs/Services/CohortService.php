<?php

namespace App\Application\Programs\Services;

use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Entities\CohortSession;
use App\Domain\Programs\Exceptions\CohortNotEmptyException;
use App\Domain\Programs\Exceptions\CohortNotFoundException;
use App\Domain\Programs\Exceptions\CohortUpdateException;
use App\Domain\Programs\Exceptions\FieldRestrictedException;
use App\Domain\Programs\Exceptions\InvalidModuleException;
use App\Domain\Programs\Exceptions\LessonNotFoundException;
use App\Domain\Programs\Exceptions\ProgramIntegrityException;
use App\Domain\Programs\Exceptions\ProgramNotFoundException;
use App\Domain\Programs\Exceptions\RestrictedStatusException;
use App\Domain\Programs\Repositories\CohortEnrollmentRepositoryInterface;
use App\Domain\Programs\Repositories\CohortRepositoryInterface;
use App\Domain\Programs\Repositories\CohortSessionRepositoryInterface;
use App\Domain\Programs\Repositories\LessonRepositoryInterface;
use App\Domain\Programs\Repositories\ModuleRepositoryInterface;
use App\Domain\Programs\Repositories\ProgramRepositoryInterface;
use App\Domain\Programs\Services\CohortServiceInterface;
use Carbon\Carbon;
use Exception;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Throwable;

readonly class CohortService implements CohortServiceInterface
{
    private const CACHE_PREFIX = 'cohort_';
    private const CACHE_TTL = 3600;

    public function __construct(
        private CohortRepositoryInterface $cohortRepository,
        private CohortEnrollmentRepositoryInterface $cohortEnrollmentRepository,
        private CohortSessionRepositoryInterface $cohortSessionRepository,
        private ProgramRepositoryInterface $programRepository,
        private LessonRepositoryInterface $lessonRepository,
        private ModuleRepositoryInterface $moduleRepository,
        private string $jitsiBaseUrl = 'https://meet.jit.si/'
    ) {}

    public function listCohortsByProgram(string $programId): Collection
    {
        return $this->cohortRepository->findByProgram($programId);
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
            'status' => 'scheduled',
        ]);

        if(!isset($data['assigned_instructor_id']))
        {
            $cohortData = array_merge($data, [
                'assigned_instructor_id' => Auth::id(),
            ]);
        }

        return $this->cohortRepository->create($cohortData);
    }

    /**
     * @throws CohortNotFoundException
     */
    public function getCohortDetails(string $id): Cohort
    {
        return cache()->remember(
            self::CACHE_PREFIX . $id,
            self::CACHE_TTL,
            function () use ($id) {
                $cohort = $this->cohortRepository->findById($id);

                if (!$cohort) {
                    throw new CohortNotFoundException();
                }

                // Eager load the full content tree
                return $cohort->load(['program.modules.lessons']);
            }
        );
    }


    /**
     * @throws RestrictedStatusException
     * @throws FieldRestrictedException
     * @throws CohortUpdateException
     */
    public function updateCohort(string $cohortId, array $data): Cohort
    {
        $cohort = $this->cohortRepository->findOrFail($cohortId);

        // 1. Prevent updates to Completed or Cancelled cohorts
        if (in_array($cohort->status, ['completed', 'cancelled'])) {
            throw new RestrictedStatusException($cohort->status);
        }

        // 2. Prevent critical changes if students are already enrolled
        $activeAndReservedCount = $this->cohortEnrollmentRepository->countActiveAndReserved($cohortId);

        if ($activeAndReservedCount > 0) {
            // Field Restrictions (Price/Program)
            foreach (['price', 'program_id'] as $field) {
                if (isset($data[$field]) && $data[$field] != $cohort->{$field}) {
                    throw new FieldRestrictedException($field);
                }
            }

            // Capacity Restriction
            if (isset($data['capacity']) && $data['capacity'] < $activeAndReservedCount) {
                throw new CohortUpdateException("Capacity cannot be reduced below the {$activeAndReservedCount} currently enrolled/reserved students.");
            }
        }

        // 3. Date change logic
        if (isset($data['start_date']) &&
            $cohort->status === 'active' &&
            Carbon::parse($data['start_date'])->ne(Carbon::parse($cohort->start_date))) {
            throw new CohortUpdateException();
        }

        if(!isset($data['assigned_instructor_id'])) {
            $data = array_merge($data, [
                'assigned_instructor_id' => $cohort->assigned_instructor_id,
            ]);
        }

        $updatedCohort = $this->cohortRepository->update($cohort, $data);

        $this->clearCohortCache($cohortId);

        return $updatedCohort;
    }

    /**
     * @throws RestrictedStatusException
     * @throws CohortNotEmptyException
     * @throws Throwable
     */
    public function deleteCohort(string $id): bool
    {
        $cohort = $this->cohortRepository->findOrFail($id);

        $occupiedSeats = $this->cohortEnrollmentRepository->countActiveAndReserved($id);
        if ($occupiedSeats > 0) {
            throw new CohortNotEmptyException($occupiedSeats);
        }

        if (in_array($cohort->status, ['active', 'completed'])) {
            throw new RestrictedStatusException($cohort->status);
        }

        $deleted = $this->cohortRepository->delete($cohort);

        $this->clearCohortCache($id);

        return $deleted;
    }

    /**
     * @throws Throwable
     */
    public function restoreCohort(string $id): bool
    {
        $this->cohortRepository->restore($id);

        $this->clearCohortCache($id);

        return true;
    }

    /**
     * @throws Exception
     */
    public function scheduleSession(string $cohortId, string $lessonId, array $data): CohortSession
    {
        // 1. Fetch the Cohort
        $cohort = $this->cohortRepository->findById($cohortId);
        if (!$cohort) {
            throw new CohortNotFoundException();
        }

        // 2. Fetch the Lesson
        $lesson = $this->lessonRepository->findById($lessonId);
        if (!$lesson) {
            throw new LessonNotFoundException("Cannot schedule session: Lesson [$lessonId] not found.");
        }

        // 3. Fetch the Module to get the Program ID
        $module = $this->moduleRepository->findById($lesson->module_id);
        if (!$module) {
            throw new InvalidModuleException("Corrupt data: Lesson has no valid module.");
        }

        // 4. THE INTEGRITY CHECK
        // Compare the Lesson's Program ID with the Cohort's Program ID
        if ($module->program_id != $cohort->program_id) {
            throw new ProgramIntegrityException("Lesson does not belong to the Program associated with this Cohort.");
        }

        $roomName = 'Radixia-' . Str::slug($cohort->name) . '-' . Str::random(10);

        $sessionData = array_merge($data, [
            'cohort_id' => $cohortId,
            'lesson_id' => $lessonId,
            'meeting_url' => ($cohort->meeting_base_url ?? $this->jitsiBaseUrl) . $roomName,
            'status' => 'scheduled'
        ]);

        return $this->cohortSessionRepository->create($sessionData);
    }


    public function active(string $cohortId): Cohort
    {
        $cohort = $this->cohortRepository->findOrFail($cohortId);

        return $this->cohortRepository->update($cohort, [
            'status' => 'active',
        ]);
    }


    public function complete(string $cohortId): Cohort
    {
        $cohort = $this->cohortRepository->findOrFail($cohortId);

        return $this->cohortRepository->update($cohort, [
            'status' => 'completed',
        ]);
    }

    public function cancel(string $cohortId): Cohort
    {
        $cohort = $this->cohortRepository->findOrFail($cohortId);

        return $this->cohortRepository->update($cohort, [
            'status' => 'cancelled',
        ]);
    }

    private function clearCohortCache(string $cohortId): void
    {
        cache()->forget(self::CACHE_PREFIX . $cohortId);
    }
}