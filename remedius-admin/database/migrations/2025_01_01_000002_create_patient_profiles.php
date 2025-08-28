<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
  public function up(): void {
    Schema::create('patient_profiles', function (Blueprint $t) {
      $t->id();
      $t->foreignId('user_id')->constrained()->cascadeOnDelete();
      $t->date('dob')->nullable();
      $t->string('gender', 16)->nullable();
      $t->json('contacts')->nullable();
      $t->json('allergies')->nullable();
      $t->timestamps();
    });
  }
  public function down(): void { Schema::dropIfExists('patient_profiles'); }
};
