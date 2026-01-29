<?php

namespace App\Application\Programs\Services;

use App\Domain\Programs\Entities\CohortEnrollment;
use App\Domain\Programs\Exceptions\CohortEnrollmentNotFoundException;
use App\Domain\Programs\Exceptions\CohortNotFoundException;
use App\Domain\Programs\Exceptions\CohortOverLimitException;
use App\Domain\Programs\Repositories\CohortEnrollmentRepositoryInterface;
use App\Domain\Programs\Repositories\CohortRepositoryInterface;
use App\Domain\Programs\Services\CohortEnrollmentServiceInterface;
use Illuminate\Support\Facades\DB;
use Throwable;

class CohortEnrollmentService implements CohortEnrollmentServiceInterface
{
    public function __construct(
        protected CohortEnrollmentRepositoryInterface $enrollmentRepo,
        protected CohortRepositoryInterface $cohortRepo
    ) {}

    /**
     * Step 1: The Initial Request (Seat Reservation)
     * @throws CohortNotFoundException
     * @throws CohortOverLimitException
     */
    public function requestEnrollment(string $userId, string $cohortId): CohortEnrollment
    {
        $cohort = $this->cohortRepo->findById($cohortId);

        if (!$cohort) {
            throw new CohortNotFoundException();
        }

        // 1. Check if they are already active
        $existing = $this->enrollmentRepo->findPending($userId, $cohortId);
        // Note: findPending logic in Repo already checks for non-expired records

        if ($existing) {
            return $existing;
        }

        // 2. Atomic Seat Check
        $occupiedSeats = $this->enrollmentRepo->countActiveAndReserved($cohortId);

        if ($occupiedSeats >= $cohort->capacity) {
            throw new CohortOverLimitException();
        }

        // 3. Create the 30-minute lock
        return $this->enrollmentRepo->create([
            'user_id' => $userId,
            'cohort_id' => $cohortId,
            'status' => 'pending',
            'expires_at' => now()->addMinutes(30),
        ]);
    }

    /**
     * Step 2: The Activation (Called by Payment Webhook)
     * @throws Throwable
     * @throws CohortEnrollmentNotFoundException
     */
    public function activateEnrollment(string $enrollmentId, string $transactionId, float $amount): CohortEnrollment
    {
        return DB::transaction(function () use ($enrollmentId, $transactionId, $amount) {
            $enrollment = $this->enrollmentRepo->findById($enrollmentId);

            if (!$enrollment) {
                throw new CohortEnrollmentNotFoundException();
            }

            // Here you would also call your TransactionRepository to save the payment record
            // $this->transactionRepo->create([...]);

            return $this->enrollmentRepo->updateStatus($enrollmentId, 'active', [
                'transaction_id' => $transactionId,
                'amount_paid' => $amount
            ]);
        });
    }

    /**
     * Step 3: The Access Guard (Used by Jitsi/UI)
     */
    public function hasAccess(string $userId, string $cohortId): bool
    {
        $enrollment = $this->enrollmentRepo->findByUserAndCohort($userId, $cohortId);
        return $enrollment && $enrollment->status === 'active';
    }
}