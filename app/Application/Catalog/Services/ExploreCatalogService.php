<?php

namespace App\Application\Catalog\Services;

use App\Domain\Catalog\Repositories\CatalogRepositoryInterface;
use App\Domain\Programs\Entities\Program;
use App\Domain\Programs\Exceptions\ProgramNotFoundException;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Collection;

readonly class ExploreCatalogService
{
    public function __construct(
        private CatalogRepositoryInterface $catalog,
        private UserRepositoryInterface $userRepository
    )
    {}

    public function explore(array $filters): LengthAwarePaginator
    {
        $paginator = $this->catalog->explore($filters);

        $paginator->getCollection()->transform(function ($item) {

            $item->duration_hours = round(
                ($item->duration_minutes ?? 0) / 60,
                1
            );

            $item->rating = round(rand(10, 50)/ 10.0 , 1);
            $item->rating_count = rand(5, 25000);

            return $item;
        });

        return $paginator;
    }

    /**
     * @throws ProgramNotFoundException
     */
    public function programDetails(string $slug): array
    {
        $program = $this->catalog->programDetails($slug);

        if (!$program) {
            throw new ProgramNotFoundException();
        }

        $instructorStats = $this->userRepository
            ->getInstructorStats($program->instructor_id);

        return [
            'program' => $program,
            'instructor_stats' => $instructorStats,
        ];
    }

    public function getProgramOverview(string $slug): ?Program
    {
        return $this->catalog->programOverview($slug);
    }

    public function getProgramCurriculum(string $slug): ?Program
    {
        return $this->catalog->programCurriculum($slug);
    }

    public function getProgramCohorts(string $slug): Collection
    {
        return $this->catalog->programCohorts($slug);
    }
}
