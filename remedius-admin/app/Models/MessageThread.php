<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class MessageThread extends Model
{
    protected $fillable = ['subject','participants'];
    protected $casts = ['participants' => 'array'];

    public function messages() { return $this->hasMany(Message::class, 'thread_id'); }
}
