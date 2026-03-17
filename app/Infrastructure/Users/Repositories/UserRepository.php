<?php

namespace App\Infrastructure\Users\Repositories;

use App\Domain\Instructors\Entities\InstructorProfile;
use App\Domain\Users\Entities\UserProfile;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Models\User;
use DateTimeInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class UserRepository implements UserRepositoryInterface
{
    public function findByEmail(string $email): ?User
    {
        return User::query()
            ->where('email', $email)
            ->first();
    }

    /**
     * @throws \Throwable
     */
    public function create(array $data): User
    {
        return DB::transaction(function () use ($data) {
            $user = User::create([
                'name' => $data['name'],
                'email' => $data['email'],
                'password' => $data['password'],
            ]);

            $avatarUrl = 'https://api.dicebear.com/9.x/shapes/svg?seed=' . urlencode($data['name']);

            UserProfile::create([
                'user_id' => $user->id,
                'avatar_url' => $avatarUrl,
                'marketing_opt_in' => $data['marketing_opt_in'] ?? false,
                'locale' => 'en',
                'timezone' => null, // Let frontend detect later
            ]);

            return $user;
        });
    }

    public function findById(string $id): ?User
    {
        return User::find($id);
    }

    public function save(User $user): void
    {
        $user->save();
    }

    public function markEmailVerified(User $user): void
    {
        if (! $user->hasVerifiedEmail()) {
            $user->markEmailAsVerified();
        }
    }

    public function setPendingEmail(User $user, string $email, string $token, DateTimeInterface $expiresAt): void
    {
        $user->forceFill([
            'pending_email' => $email,
            'pending_email_token' => $token,
            'pending_email_expires_at' => $expiresAt,
        ])->save();
    }

    public function setEmail(User $user, string $email): void
    {
        $user->forceFill([
            'email' => $email,
            'email_verified_at' => now(),
        ])->save();
    }

    public function clearPendingEmail(User $user): void
    {
        $user->forceFill([
            'pending_email' => null,
            'pending_email_token' => null,
        ])->save();
    }

    public function updatePassword(User $user, string $newPassword): void
    {
        $user->forceFill([
            'password' => $newPassword,
            'remember_token' => Str::random(60),
        ])->save();
    }

    public function getInstructorStats(string $userId): array
    {
        return [
            'courses' => DB::table('programs')
                ->where('instructor_id', $userId)
                ->count(),

            'students' => DB::table('cohorts as c')
                ->join('cohort_enrollments as ce', 'ce.cohort_id', '=', 'c.id')
                ->join('programs as p', 'p.id', '=', 'c.program_id')
                ->where('p.instructor_id', $userId)
                ->distinct('ce.user_id')
                ->count('ce.user_id'),

            'rating_avg' => DB::table('reviews')
                ->where('reviewable_type', InstructorProfile::class)
                ->whereIn('reviewable_id', function ($q) use ($userId) {
                    $q->select('id')
                        ->from('instructor_profiles')
                        ->where('user_id', $userId);
                })
                ->avg('rating'),

            'rating_count' => DB::table('reviews')
                ->where('reviewable_type', InstructorProfile::class)
                ->whereIn('reviewable_id', function ($q) use ($userId) {
                    $q->select('id')
                        ->from('instructor_profiles')
                        ->where('user_id', $userId);
                })
                ->count(),
        ];
    }

}
