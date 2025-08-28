<?php

namespace App\Http\Controllers;

use App\Models\Appointment;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

class AppointmentController extends Controller
{
    public function store(Request $request)
    {
        $data = $request->validate([
            'doctor_id' => ['required','integer','exists:users,id'],
            'patient_id' => ['required','integer','exists:users,id'],
            'start' => ['required','date'],
            'end' => ['required','date','after:start'],
            'reason' => ['nullable','string'],
        ]);

        $overlaps = Appointment::query()
            ->where('doctor_id', $data['doctor_id'])
            ->where(function ($q) use ($data) {
                $start = $data['start'];
                $end = $data['end'];
                $q->whereBetween('start', [$start, $end])
                  ->orWhereBetween('end', [$start, $end])
                  ->orWhere(function ($qq) use ($start, $end) {
                      $qq->where('start', '<=', $start)
                         ->where('end', '>=', $end);
                  });
            })
            ->exists();

        if ($overlaps) {
            return response()->json([
                'message' => 'Overlapping appointment for doctor',
                'errors' => ['start' => ['overlap'], 'end' => ['overlap']],
            ], 422);
        }

        $appt = Appointment::create($data);
        return response()->json($appt, 201);
    }
}

