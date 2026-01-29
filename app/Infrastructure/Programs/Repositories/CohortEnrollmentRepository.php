<?php

namespace App\Infrastructure\Programs\Repositories;

use App\Domain\Programs\Entities\CohortEnrollment;
use App\Domain\Programs\Repositories\CohortEnrollmentRepositoryInterface;

class CohortEnrollmentRepository implements CohortEnrollmentRepositoryInterface
{
    public function findById(string $id): ?CohortEnrollment
    {
        return CohortEnrollment::find($id);
    }

    public function findPending(string $userId, string $cohortId): ?CohortEnrollment
    {
        return CohortEnrollment::where('user_id', $userId)
            ->where('cohort_id', $cohortId)
            ->where('status', 'pending')
            ->where('expires_at', '>', now())
            ->first();
    }

    /**
     * The most critical method for seat management.
     * Counts:
     * 1. Everyone with status 'active'
     * 2. Everyone with status 'pending' whose reservation hasn't expired.
     */
    public function countActiveAndReserved(string $cohortId): int
    {
        return CohortEnrollment::where('cohort_id', $cohortId)
            ->where(function ($query) {
                $query->where('status', 'active')
                    ->orWhere(function ($q) {
                        $q->where('status', 'pending')
                            ->where('expires_at', '>', now());
                    });
            })->count();
    }

    public function create(array $data): CohortEnrollment
    {
        return CohortEnrollment::create($data);
    }

    public function updateStatus(string $id, string $status, array $extraData = []): CohortEnrollment
    {
        $enrollment = CohortEnrollment::findOrFail($id);

        $updateData = array_merge(['status' => $status], $extraData);

        // If becoming active, set the activation timestamp
        if ($status === 'active') {
            $updateData['activated_at'] = now();
            $updateData['expires_at'] = null; // Clear the timer
        }

        $enrollment->update($updateData);

        return $enrollment;
    }

    public function findByUserAndCohort(string $userId, string $cohortId): ?CohortEnrollment
    {
        return CohortEnrollment::where('user_id', $userId)
            ->where('cohort_id', $cohortId)
            ->first();
    }
}