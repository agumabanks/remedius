<?php

it('shows health', function () {
    $this->getJson('/api/health')->assertOk()->assertJson(['ok'=>true]);
});
