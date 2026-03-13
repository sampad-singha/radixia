<?php

namespace App\Application\Catalog\Services;

use App\Domain\Catalog\Repositories\CatalogRepositoryInterface;
use Illuminate\Pagination\LengthAwarePaginator;

readonly class ExploreCatalogService
{
    public function __construct(
        private CatalogRepositoryInterface $catalog,
    )
    {}

    public function explore(array $filters): LengthAwarePaginator
    {
        $paginator = $this->catalog->explore($filters);

        $paginator->getCollection()->transform(function ($item) {

            $item->price = $item->cohort_price ?? 0;

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
}
