<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
  public function up(): void {
    Schema::create('appointments', function (Blueprint $t) {
      $t->id();
      $t->foreignId('patient_id')->constrained('users')->cascadeOnDelete();
      $t->foreignId('doctor_id')->constrained('users')->cascadeOnDelete();
      $t->dateTime('start');
      $t->dateTime('end');
      $t->enum('status', ['scheduled','rescheduled','cancelled','completed','no_show'])->default('scheduled');
      $t->string('reason')->nullable();
      $t->timestamps();
      $t->unique(['doctor_id','start','end']);
    });
  }
  public function down(): void { Schema::dropIfExists('appointments'); }
};
