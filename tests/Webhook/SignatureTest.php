<?php

namespace Metigy\PHPSDK\Webhook {

    function time() {
        if (\Metigy\PHPSDK\Tests\Webhook\SignatureTest::$overrideTime === false) {
            return \time();
        }

        return \Metigy\PHPSDK\Tests\Webhook\SignatureTest::$currentTime;
    }
}


namespace Metigy\PHPSDK\Tests\Webhook {

    use \Metigy\PHPSDK\Webhook\Signature;
    use \Metigy\PHPSDK\Util\UtilInterface;

    class SignatureTest extends \PHPUnit_Framework_TestCase
    {
        public static $overrideTime = false;
        public static $currentTime;

        public function testSignPayloadStringPayloadWithTimestamp() {
            $payload = '{"id":"1","text":"test"}';
            $secret = '12345';
            $timestamp = 1495602649;

            $expectedResult = "t=$timestamp,v=864c4156d689a3492ef0a9ece0367a4ded2f48890280a4958999e6bf730db7f4";

            $util = $this->getMockBuilder(UtilInterface::class)->getMock();
            $signatureObj = new Signature($util);

            $result = $signatureObj->signPayload($payload, $secret, $timestamp);

            $this->assertEquals($expectedResult, $result);
        }

        public function testSignPayloadStringPayloadWithoutTimestamp() {
            self::$overrideTime = true;
            self::$currentTime = 1495602649;

            $payload = '{"id":"1","text":"test"}';
            $secret = '12345';

            $expectedResult = "t=" . self::$currentTime
                . ",v=864c4156d689a3492ef0a9ece0367a4ded2f48890280a4958999e6bf730db7f4";

            $util = $this->getMockBuilder(UtilInterface::class)->getMock();
            $signatureObj = new Signature($util);

            $result = $signatureObj->signPayload($payload, $secret);

            $this->assertEquals($expectedResult, $result);
        }

        public function testSignPayloadNonStringPayload() {
            $payload = [
                'id' => '1',
                'text' => 'test',
            ];
            $secret = '12345';
            $timestamp = 1495602649;

            $util = $this->getMockBuilder(UtilInterface::class)->getMock();
            $signatureObj = new Signature($util);

            $expectedResult = "t=$timestamp,v=864c4156d689a3492ef0a9ece0367a4ded2f48890280a4958999e6bf730db7f4";
            $result = $signatureObj->signPayload($payload, $secret, $timestamp);

            $this->assertEquals($expectedResult, $result);
        }

        public function testVerifyPayloadSuccessful() {
            self::$overrideTime = true;
            self::$currentTime = 1495602655;

            $payload = [
                'id' => '1',
                'text' => 'test',
            ];
            $secret = '12345';
            $timestamp = 1495602649;
            $tolerance = 300;
            $signature = "t=$timestamp,v=864c4156d689a3492ef0a9ece0367a4ded2f48890280a4958999e6bf730db7f4";

            $util = $this->getMockBuilder(UtilInterface::class)
                ->getMock();
            $util->expects($this->once())
                ->method('secureCompare')
                ->will($this->returnValue(true));

            $signatureObj = new Signature($util);
            $result = $signatureObj->verifyPayload($payload, $signature, $secret, $tolerance);

            $this->assertTrue($result);
        }

        /**
         * @expectedException \Metigy\PHPSDK\Webhook\Exception\SignatureVerificationException
         * @expectedExceptionMessage Unable to extract timestamp from signature
         */
        public function testVerifyPayloadInvalidTimestamp()
        {
            $payload = [
                'id' => '1',
                'text' => 'test',
            ];
            $secret = '12345';
            $timestamp = 1495602649;
            $signature = "$timestamp,v=864c4156d689a3492ef0a9ece0367a4ded2f48890280a4958999e6bf730db7f4";

            $util = $this->getMockBuilder(UtilInterface::class)
                ->getMock();
            $util->expects($this->never())
                ->method('secureCompare')
                ->will($this->returnValue(true));

            $signatureObj = new Signature($util);
            $signatureObj->verifyPayload($payload, $signature, $secret);
        }

        /**
         * @expectedException \Metigy\PHPSDK\Webhook\Exception\SignatureVerificationException
         * @expectedExceptionMessage Unable to extract timestamp from signature
         */
        public function testVerifyPayloadNonNumericTimestamp()
        {
            $payload = [
                'id' => '1',
                'text' => 'test',
            ];
            $secret = '12345';
            $timestamp = 'asdfghjkl';
            $signature = "t=$timestamp,v=864c4156d689a3492ef0a9ece0367a4ded2f48890280a4958999e6bf730db7f4";

            $util = $this->getMockBuilder(UtilInterface::class)
                ->getMock();
            $util->expects($this->never())
                ->method('secureCompare')
                ->will($this->returnValue(true));

            $signatureObj = new Signature($util);
            $signatureObj->verifyPayload($payload, $signature, $secret);
        }

        /**
         * @expectedException \Metigy\PHPSDK\Webhook\Exception\SignatureVerificationException
         * @expectedExceptionMessage Unable to extract value from signature
         */
        public function testVerifyPayloadInvalidValue() {
            $payload = [
                'id' => '1',
                'text' => 'test',
            ];
            $secret = '12345';
            $timestamp = 1495602649;
            $signature = "t=$timestamp,864c4156d689a3492ef0a9ece0367a4ded2f48890280a4958999e6bf730db7f4";

            $util = $this->getMockBuilder(UtilInterface::class)
                ->getMock();
            $util->expects($this->never())
                ->method('secureCompare')
                ->will($this->returnValue(true));

            $signatureObj = new Signature($util);
            $signatureObj->verifyPayload($payload, $signature, $secret);
        }

        /**
         * @expectedException \Metigy\PHPSDK\Webhook\Exception\SignatureVerificationException
         * @expectedExceptionMessage Value mismatch the expected signature for payload
         */
        public function testVerifyPayloadMismatch() {
            $payload = [
                'id' => '1',
                'text' => 'test',
            ];
            $secret = '12345';
            $timestamp = 1495602649;
            // expected signature: "t=$timestamp,v=864c4156d689a3492ef0a9ece0367a4ded2f48890280a4958999e6bf730db7f4";
            $signature = "t=$timestamp,v=4c4156d689a3492ef0a9ece0367a4ded2f48890280a4958999e6bf730db7f4";

            $util = $this->getMockBuilder(UtilInterface::class)
                ->getMock();
            $util->expects($this->once())
                ->method('secureCompare')
                ->will($this->returnValue(false));

            $signatureObj = new Signature($util);
            $signatureObj->verifyPayload($payload, $signature, $secret);
        }

        /**
         * @expectedException \Metigy\PHPSDK\Webhook\Exception\SignatureVerificationException
         * @expectedExceptionMessage Timestamp outside the tolerance zone
         */
        public function testVerifyPayloadExpiredTimestamp() {
            self::$overrideTime = true;
            self::$currentTime = 1495602669;

            $payload = [
                'id' => '1',
                'text' => 'test',
            ];
            $secret = '12345';
            $timestamp = 1495602649;
            $signature = "t=$timestamp,v=864c4156d689a3492ef0a9ece0367a4ded2f48890280a4958999e6bf730db7f4";
            $tolerance = 10;

            $util = $this->getMockBuilder(UtilInterface::class)
                ->getMock();
            $util->expects($this->once())
                ->method('secureCompare')
                ->will($this->returnValue(true));

            $signatureObj = new Signature($util);
            $signatureObj->verifyPayload($payload, $signature, $secret, $tolerance);
        }
    }
}
