<?php

namespace App\Http\Controllers\Api\V1\Catalog;

use App\Application\Catalog\Services\ExploreCatalogService;
use App\Domain\Programs\Exceptions\ProgramNotFoundException;
use App\Http\Controllers\Controller;
use App\Http\Resources\ProgramCohortResource;
use App\Http\Resources\ProgramCurriculumResource;
use App\Http\Resources\ProgramDetailsResource;
use App\Http\Resources\ProgramOverviewResource;

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

    /**
     * @throws ProgramNotFoundException
     */
    public function programDetails(string $slug)
    {
        $result = $this->explore->programDetails($slug);

        return response()->json([
            'data' => new ProgramDetailsResource(
                $result['program'],
                $result['instructor_stats']
            )
        ]);
    }

    public function programOverview(string $slug)
    {
        $program = $this->explore->getProgramOverview($slug);

        return response()->json([
            'data' => new ProgramOverviewResource($program)
        ]);
    }

    public function programCurriculum(string $slug)
    {
        $program = $this->explore->getProgramCurriculum($slug);

        return response()->json([
            'data' => new ProgramCurriculumResource($program)
        ]);
    }

    public function programCohorts(string $slug)
    {
        $cohorts = $this->explore->getProgramCohorts($slug);

        return response()->json([
            'data' => ProgramCohortResource::collection($cohorts)
        ]);
    }
}
