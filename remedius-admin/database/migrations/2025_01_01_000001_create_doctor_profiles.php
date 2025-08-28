<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
  public function up(): void {
    Schema::create('doctor_profiles', function (Blueprint $t) {
      $t->id();
      $t->foreignId('user_id')->constrained()->cascadeOnDelete();
      $t->string('specialty')->nullable();
      $t->text('bio')->nullable();
      $t->json('licenses')->nullable();
      $t->boolean('is_verified')->default(false);
      $t->timestamps();
    });
  }
  public function down(): void { Schema::dropIfExists('doctor_profiles'); }
};
