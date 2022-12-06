<?php
namespace OGBitBlt\Cryptography;
/**
 * Generates a keyfile of unicode characters that will be used to encrypt and decrypt
 * our data.
 * @author Anthony Davis <ogbitblt@pm.me>
 * @package ogbitblit-cryptography
 */
class KeyFile 
{
    /**
     * @var array of the unicode characters we use for encryption
     */
    private static $_c = [];
    /**
     * returns the character array if it is populated, if not it will
     * initialize the array and then return it.
     */
    public static function _gchs()
    {
        if(count(self::$_c)<=1){
            for($i=32;$i<=126;$i++)array_unshift(self::$_c,\IntlChar::chr($i));
        }
        return self::$_c;
    }
    /**
     * Generate a random string of unicode characters of the length specified.
     * @param int length is the length of the string to return
     * @return returns a string of random characters from the character array the 
     * length specified by length parameter.
     */
    public static function GenerateKeyFile(int $l=10000)
    {
        $r='';
        for($i=0;$i<$l;$i++)$r=$r.self::_gchs()[rand(0,count(self::_gchs())-1)]; 
        return $r;
    }
}
