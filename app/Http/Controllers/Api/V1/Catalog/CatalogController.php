<?php

namespace App\Http\Controllers\Api\V1\Catalog;

use App\Application\Catalog\Services\ExploreCatalogService;
use App\Http\Controllers\Controller;

class CatalogController extends Controller
{
    public function __construct(
        private readonly ExploreCatalogService $explore
    ){}

    public function explore()
    {
        $filters = request()->only([
            'q',
            'type',
            'price_type',
            'price_min',
            'price_max',
            'rating_min',
            'level',
            'language',
            'duration',
            'topics',
            'sort',
            'page',
            'per_page',
        ]);

        $data = $this->explore->explore($filters);

        return response()->json(['data' => $data]);
    }

    public function programDetails(string $slug)
    {
        $data = $this->explore->programDetails($slug);

        return response()->json(['data' => $data]);
    }
}
