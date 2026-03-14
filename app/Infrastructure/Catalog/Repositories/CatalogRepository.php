<?php

namespace App\Infrastructure\Catalog\Repositories;

use App\Domain\Catalog\Repositories\CatalogRepositoryInterface;
use App\Domain\Programs\Entities\Program;
use App\Domain\Programs\Enums\CohortStatus;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\DB;

class CatalogRepository implements CatalogRepositoryInterface
{
    public function explore(array $filters): LengthAwarePaginator
    {
        $query = $this->programSubquery();

//        $courses  = $this->courseSubquery();
//
//        $catalog = $programs->unionAll($courses);

//        $query = DB::query()->fromSub($catalog, 'catalog');

        $this->applyFilters($query, $filters);

        $this->applySorting($query, $filters);

        $perPage = $filters['per_page'] ?? 12;

        return $query->paginate($perPage);
    }

    private function programSubquery(): Builder
    {
        return Program::query()
            ->with([
                'instructor:id,name',
                'topics:id,name'
            ])
            ->select([
                'programs.*',
                DB::raw("'program' as type")
            ])
            ->selectSub(function ($query) {
                $query->from('modules')
                    ->join('lessons', 'lessons.module_id', '=', 'modules.id')
                    ->whereColumn('modules.program_id', 'programs.id')
                    ->selectRaw('COUNT(lessons.id)');
            }, 'lesson_count')
            ->selectSub(function ($query) {
                $query->from('modules')
                    ->join('lessons', 'lessons.module_id', '=', 'modules.id')
                    ->whereColumn('modules.program_id', 'programs.id')
                    ->selectRaw('COALESCE(SUM(lessons.duration_minutes),0)');
            }, 'duration_minutes')
            ->selectSub(function ($query) {
                $query->from('cohorts')
                    ->join('cohort_enrollments', 'cohort_enrollments.cohort_id', '=', 'cohorts.id')
                    ->whereColumn('cohorts.program_id', 'programs.id')
                    ->selectRaw('COUNT(cohort_enrollments.id)');
            }, 'enrollments_count')
            ->withMin([
                'cohorts as price' => function ($query) {
                    $query->whereIn('status', [
                        CohortStatus::SCHEDULED,
                        CohortStatus::ACTIVE
                    ]);
                }
            ], 'price')
            ->where('status', 'published')
            ->whereHas('cohorts', function ($query) {
                $query->whereIn('status', [
                    CohortStatus::SCHEDULED,
                    CohortStatus::ACTIVE
                ]);
            });
    }

    private function applyFilters(Builder $query, array $filters): void
    {
        if (!empty($filters['q'])) {
            $query->where(function ($q) use ($filters) {
                $q->where('title', 'like', "%{$filters['q']}%")
                    ->orWhere('description', 'like', "%{$filters['q']}%")
                    ->orWhereHas('topics', fn($t) => $t->where('name', 'like', "%{$filters['q']}%")
                    )
                    ->orWhereHas('instructor', fn($i) => $i->where('name', 'like', "%{$filters['q']}%")
                    );
            });
        }

        if (!empty($filters['level'])) {
            $query->whereIn('level', (array)$filters['level']);
        }

        if (!empty($filters['topics'])) {
            $query->whereHas('topics', function ($q) use ($filters) {
                $q->whereIn('slug', (array)$filters['topics']);
            });
        }

        if (!empty($filters['price_min'])) {
            $query->having('price', '>=', $filters['price_min']);
        }

        if (!empty($filters['price_max'])) {
            $query->having('price', '<=', $filters['price_max']);
        }

        if (($filters['price_type'] ?? null) === 'free') {
            $query->having('price', '=', 0);
        }

        if (($filters['price_type'] ?? null) === 'paid') {
            $query->having('price', '>', 0);
        }

        if (!empty($filters['duration'])) {

            if ($filters['duration'] === 'short') {
                $query->having('duration_minutes', '<=', 300);
            }

            if ($filters['duration'] === 'medium') {
                $query->havingBetween('duration_minutes', [300, 1200]);
            }

            if ($filters['duration'] === 'long') {
                $query->having('duration_minutes', '>', 1200);
            }
        }

        if (!empty($filters['type']) && !in_array('program', (array)$filters['type'])) {
            $query->whereRaw('1 = 0');
        }
    }

    private function applySorting(Builder $query, array $filters): void
    {
        switch ($filters['sort'] ?? 'newest') {

            case 'price_low':
                $query->orderBy('price', 'asc');
                break;

            case 'price_high':
                $query->orderBy('price', 'desc');
                break;

            case 'popular':
                $query->orderByDesc('enrollments_count');
                break;

            case 'newest':
            default:
                $query->orderByDesc('programs.created_at');
        }
    }
}
