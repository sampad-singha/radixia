<?php

namespace App\Domain\Catalog\Repositories;

use Illuminate\Pagination\LengthAwarePaginator;

interface CatalogRepositoryInterface
{
    public function explore(array $filters): LengthAwarePaginator;
}
