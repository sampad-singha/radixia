<?php

use App\Http\Controllers\Api\V1\Catalog\CatalogController;

Route::prefix('catalog')->group(function () {
    Route::get('/', [CatalogController::class, 'explore']);
});
