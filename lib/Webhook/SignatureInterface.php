<?php

namespace Metigy\PHPSDK\Webhook;

interface SignatureInterface
{
    public function signPayload($payload, $secret);
    public function verifyPayload($payload, $signature, $secret, $tolerance = null);
}