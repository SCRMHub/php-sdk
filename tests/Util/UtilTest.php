<?php

namespace Metigy\PHPSDK\Util {

    function function_exists($functionName) {
        if (\Metigy\PHPSDK\Tests\Util\UtilTest::$hashEqualsExists === false) {
            return false;
        }

        $result = \function_exists($functionName);

        if ($functionName == 'hash_equals' && $result === false) {
            return true;
        }

        return $result;
    }

    function hash_equals($a, $b) {
        if (\function_exists('hash_equals')) {
            return \hash_equals($a,$b);
        }

        return true;
    }
}

namespace Metigy\PHPSDK\Tests\Util {

    use \Metigy\PHPSDK\Util\Util;

    class UtilTest extends \PHPUnit_Framework_TestCase
    {
        public static $hashEqualsExists;

        public function testSecureCompareEqualValues()
        {
            self::$hashEqualsExists = false;

            $a = crypt('Alpha', '$salt$');
            $b = crypt('Alpha', '$salt$');

            $util = new Util();
            $result = $util->secureCompare($a, $b);

            $this->assertTrue($result);
        }

        public function testSecureCompareUnequalValues()
        {
            self::$hashEqualsExists = false;

            $a = crypt('Alpha', '$salt$');
            $b = crypt('Bravo', '$salt$');

            $util = new Util();
            $result = $util->secureCompare($a, $b);

            $this->assertFalse($result);
        }

        public function testSecureCompareEqualValuesWithHashEquals()
        {
            self::$hashEqualsExists = true;

            $a = crypt('Alpha', '$salt$');
            $b = crypt('Alpha', '$salt$');

            $util = new Util();
            $result = $util->secureCompare($a, $b);

            $this->assertTrue($result);
        }

        public function testSecureCompareUnequalValuesLengths()
        {
            self::$hashEqualsExists = false;

            $a = 'Alpha';
            $b = 'Beta';

            $util = new Util();
            $result = $util->secureCompare($a, $b);

            $this->assertFalse($result);
        }
    }
}
