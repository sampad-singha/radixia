<?php

namespace App\Application\Programs\Services;

use App\Domain\Programs\Entities\Cohort;
use App\Domain\Programs\Entities\CohortSession;
use App\Domain\Programs\Exceptions\CohortNotFoundException;
use App\Domain\Programs\Exceptions\InvalidModuleException;
use App\Domain\Programs\Exceptions\LessonNotFoundException;
use App\Domain\Programs\Exceptions\ProgramIntegrityException;
use App\Domain\Programs\Exceptions\ProgramNotFoundException;
use App\Domain\Programs\Repositories\CohortRepositoryInterface;
use App\Domain\Programs\Repositories\CohortSessionRepositoryInterface;
use App\Domain\Programs\Repositories\LessonRepositoryInterface;
use App\Domain\Programs\Repositories\ModuleRepositoryInterface;
use App\Domain\Programs\Repositories\ProgramRepositoryInterface;
use App\Domain\Programs\Services\CohortServiceInterface;
use Exception;
use Illuminate\Support\Str;

readonly class CohortService implements CohortServiceInterface
{
    public function __construct(
        private CohortRepositoryInterface $cohortRepository,
        private CohortSessionRepositoryInterface $cohortSessionRepository,
        private ProgramRepositoryInterface $programRepository,
        private LessonRepositoryInterface $lessonRepository,
        private ModuleRepositoryInterface $moduleRepository,
        private string $jitsiBaseUrl = 'https://meet.jit.si/'
    ) {}

    /**
     * @throws ProgramNotFoundException
     */
    public function createCohort(array $data): Cohort
    {
        // FAIL FAST: Check if the program exists before doing anything else
        $program = $this->programRepository->findById($data['program_id']);

        if (!$program) {
            throw new ProgramNotFoundException("Cannot create cohort: Program [{$data['program_id']}] not found.");
        }

        $cohortData = array_merge($data, [
            'status' => 'scheduled',
        ]);

        return $this->cohortRepository->create($cohortData);
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
            throw new LessonNotFoundException("Cannot schedule session: Lesson [{$lessonId}] not found.");
        }

        // 3. Fetch the Module to get the Program ID
        $module = $this->moduleRepository->findById($lesson->module_id);
        if (!$module) {
            throw new InvalidModuleException("Corrupt data: Lesson has no valid module.");
        }

        // 4. THE INTEGRITY CHECK
        // Compare the Lesson's Program ID with the Cohort's Program ID
        if ($module->program_id !== $cohort->program_id) {
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

    public function update(string $cohortId, array $data): Cohort
    {
        $cohort = $this->cohortRepository->findOrFail($cohortId);

        return $this->cohortRepository->update($cohort, $data);
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
}