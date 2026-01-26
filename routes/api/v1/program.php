<?php

use App\Http\Controllers\Api\V1\Program\ProgramController;
use Illuminate\Support\Facades\Route;

// All routes here are scoped to 'v1/user' and require 'auth:sanctum'
Route::prefix('programs')->group(function () {

    Route::middleware(['auth:sanctum', 'ability:access-api'])->group(function () {
        Route::post('/' , [ProgramController::class, 'createProgram']);
        Route::put('/{program}' , [ProgramController::class, 'updateProgram']);
    });

    Route::get('/', [ProgramController::class, 'listPublishedPrograms']);
    Route::get('/{slugOrId}', [ProgramController::class, 'getProgramDetails']);
});
