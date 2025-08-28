<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ChatController;

Route::get('/health', fn() => ['ok'=>true]);

Route::middleware('auth:sanctum')->group(function () {
    Route::post('/threads/{thread}/messages', [ChatController::class, 'send']);
    // TODO: add auth, appointments, prescriptions, payments endpoints
});
