<?php

use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(function () {
    require __DIR__ . '/api/v1/auth.php';
    require __DIR__ . '/api/v1/user.php';
    require __DIR__ . '/api/v1/instructor.php';
    require __DIR__ . '/api/v1/program.php';
});
