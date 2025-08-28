<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
  public function up(): void {
    Schema::create('availabilities', function (Blueprint $t) {
      $t->id();
      $t->foreignId('doctor_id')->constrained('users')->cascadeOnDelete();
      $t->dateTime('start');
      $t->dateTime('end');
      $t->boolean('recurring')->default(false);
      $t->string('rrule')->nullable();
      $t->timestamps();
      $t->index(['doctor_id','start','end']);
    });
  }
  public function down(): void { Schema::dropIfExists('availabilities'); }
};
