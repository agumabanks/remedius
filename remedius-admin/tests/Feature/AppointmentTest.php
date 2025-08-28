<?php

use Illuminate\Foundation\Testing\RefreshDatabase;
use App\Models\User;
use App\Models\Appointment;

uses(RefreshDatabase::class);

it('prevents overlapping appointments (example)', function () {
    $doctor = User::factory()->create();
    $patient = User::factory()->create();

    Appointment::create([
        'doctor_id'=>$doctor->id,'patient_id'=>$patient->id,
        'start'=>'2025-09-01T10:00:00','end'=>'2025-09-01T10:30:00'
    ]);

    $resp = $this->postJson('/api/appointments', [
        'doctor_id'=>$doctor->id, 'patient_id'=>$patient->id,
        'start'=>'2025-09-01T10:15:00', 'end'=>'2025-09-01T10:45:00'
    ]);

    $resp->assertStatus(422); // implement validation in controller
});
