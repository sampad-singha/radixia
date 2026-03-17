<?php

namespace App\Domain\Catalog\Repositories;

use App\Domain\Programs\Entities\Program;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Collection;

interface CatalogRepositoryInterface
{
    public function explore(array $filters): LengthAwarePaginator;
    public function programDetails(string $slug): ?Program;
    public function programCurriculum(string $slug): ?Program;
    public function programCohorts(string $slug): Collection;
}
