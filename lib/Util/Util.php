<?php

namespace SCRMHub\PHPSDK\Util;

class Util implements UtilInterface
{
    /**
     * Compares two strings for equality. The time taken is independent of the
     * number of characters that match.
     *
     * @param string $a one of the strings to compare.
     * @param string $b the other string to compare.
     * @return bool true if the strings are equal, false otherwise.
     */
    public function secureCompare($a, $b)
    {
        if (function_exists('hash_equals')) {
            return hash_equals($a, $b);
        }

        if (strlen($a) != strlen($b)) {
            return false;
        }

        $result = 0;
        for ($i = 0; $i < strlen($a); $i++) {
            $result |= ord($a[$i]) ^ ord($b[$i]);
        }

        return ($result == 0);
    }
}