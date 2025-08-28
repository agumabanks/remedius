<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ChatController;
use App\Http\Controllers\AppointmentController;

Route::get('/health', fn() => ['ok'=>true]);

// MVP endpoints used by tests
Route::post('/appointments', [AppointmentController::class, 'store']);

Route::middleware('auth:sanctum')->group(function () {
    Route::post('/threads/{thread}/messages', [ChatController::class, 'send']);
    // TODO: add auth, appointments, prescriptions, payments endpoints
});
