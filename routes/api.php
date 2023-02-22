<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/


//public routes

Route::post('/register',[AuthController::class,'Register']);
Route::post('/login',[AuthController::class,'login']);
//protected routes
Route::middleware(['auth:sanctum'])->group(function () {
Route::post('/logout',[AuthController::class,'logout']);

    Route::get('/', function () {
        return "its protected";
    });
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
});
