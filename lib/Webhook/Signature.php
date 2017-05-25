<?php

namespace Metigy\PHPSDK\Webhook;


use Metigy\PHPSDK\Util;
use Metigy\PHPSDK\Webhook\Exception\SignatureVerificationException;


/**
 * Class Signature
 * Provides methods to sign and verify a payload
 *
 * Signature structure is "t=timestamp,v=value".
 * Value is the signed payload, which is hashed value of "timestamp.payload".
 * "timestamp.payload" is referred to as timed payload.
 *
 * @package Metigy\PHPSDK\Webhook
 */
class Signature implements SignatureInterface
{
    protected $util;

    public function __construct(Util\UtilInterface $util)
    {
        $this->util = $util;
    }

    /**
     * Signs payload with $timestamp and $secret
     *
     * @param string $payload
     * @param string $secret
     * @param string $timestamp
     * @return string
     */
    public function signPayload($payload, $secret, $timestamp = 'now')
    {
        if ($timestamp == 'now') {
            $timestamp = time();
        }

        $payload = is_string($payload) ? $payload : json_encode($payload);
        $timedPayload = "$timestamp.$payload";
        $value = $this->computeSignature($timedPayload, $secret);

        $signature = "t=$timestamp,v=$value";
        return $signature;
    }

    /**
     * Verifies the signature validity.
     * Throws a SignatureVerificationException if the verification fails for any reason.
     *
     * @param string $payload the payload sent by source.
     * @param string $signature the contents of the signature sent by source.
     * @param string $secret secret used to generate the signature.
     * @param int $tolerance maximum difference allowed between the signature's
     *  timestamp and the current time
     * @throws SignatureVerificationException if the verification fails.
     */
    public function verifyPayload($payload, $signature, $secret, $tolerance = null)
    {
        $timestamp = $this->getTimestamp($signature);
        $value = $this->getValue($signature);

        $payload = is_string($payload) ? $payload : json_encode($payload);
        $timedPayload = "$timestamp.$payload";
        $expectedValue = $this->computeSignature($timedPayload, $secret);

        if ($this->util->secureCompare($expectedValue, $value) === false) {
            throw new SignatureVerificationException(
                "Value mismatch the expected signature for payload"
            );
        }

        // Check if timestamp is within tolerance
        if (($tolerance > 0) && ((time() - $timestamp) > $tolerance)) {
            throw new SignatureVerificationException(
                "Timestamp outside the tolerance zone"
            );
        }

        return true;
    }

    /**
     * Extracts the timestamp in a signature.
     *
     * @param string $signature
     * @return int the timestamp contained in the signature, or -1 if no valid
     *  timestamp is found
     */
    private function getTimestamp($signature)
    {
        $items = explode(",", $signature);

        foreach ($items as $item) {
            $itemParts = explode("=", $item, 2);

            if ($itemParts[0] != "t") {
                continue;
            }

            if (is_numeric($itemParts[1])) {
                return intval($itemParts[1]);
            }

            break;
        }

        throw new SignatureVerificationException(
            "Unable to extract timestamp from signature"
        );
    }

    /**
     * Extracts signed payload value in a signature
     *
     * @param string $signature
     * @return string signature value
     */
    private function getValue($signature)
    {
        $items = explode(",", $signature);

        foreach ($items as $item) {
            $itemParts = explode("=", $item, 2);
            if ($itemParts[0] == 'v') {
                return $itemParts[1];
            }
        }

        throw new SignatureVerificationException(
            "Unable to extract value from signature"
        );
    }

    /**
     * Computes the signature for a given payload and secret.
     *
     * @param string $payload the payload to sign.
     * @param string $secret the secret used to generate the signature.
     * @return string the signature as a string.
     */
    private function computeSignature($payload, $secret)
    {
        return hash_hmac("sha256", $payload, $secret);
    }
}