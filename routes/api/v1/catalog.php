<?php

use App\Http\Controllers\Api\V1\Catalog\CatalogController;

Route::prefix('catalog')->group(function () {
    Route::get('/', [CatalogController::class, 'explore']);
    Route::get('/programs/{slug}', [CatalogController::class, 'programDetails']);
    Route::get('/programs/{slug}/overview', [CatalogController::class, 'programOverview']);
    Route::get('/programs/{slug}/curriculum', [CatalogController::class, 'programCurriculum']);
    Route::get('/programs/{slug}/cohorts', [CatalogController::class, 'programCohorts']);
});
