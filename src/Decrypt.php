<?php
namespace OGBitBlt\Cryptography;

use OGBitBlt\Cryptography\KeyFile;

/**
 * Handles decrypting of data.
 * @author Anthony Davis <ogbitblt@pm.me>
 * @package ogbitblt-cryptography
 */
class Decrypt
{
    /**
     * DecryptUsingKeyFile --
     * @param string $msg The encrypted message 
     * @param string $kf The key file for decrypting the message
     * @return string The decrypted string 
     */
    public static function DecryptUsingKeyFile($msg,$kf) : string 
    {
        $r="";
        for($i=0;$i<strlen($msg);$i++){
            if(
                (
                    $o = (
                        array_search(
                            $msg[$i],
                            KeyFile::_gchs(),
                            false
                        ) - 
                        array_search(
                            $kf[$i],
                            KeyFile::_gchs(),
                            false
                        )
                    )
                ) < 0 
            ) $o = $o + count(KeyFile::_gchs());
            $r = $r . KeyFile::_gchs()[$o];
        }
        return $r;
    }

    /**
     * This function accepts a single parameter created by 
     * a call to EncryptCombined. It will split this parameter
     * into the keyfile and encrypted data, then call the 
     * standard DecryptUsingKeyFile API to decrypt it.
     *
     * @param string $data this parameter is a combination of the 
     *                      keyfile and the encrypted data
     * @return string the decrypted data 
     */
    public static function DecryptCombined(string $data) : string 
    {
        $d='';
        $k='';
        for($i=0;$i<strlen($data);$i++){
            $k=$k.$data[$i];
            $i++;
            $d=$d.$data[$i];
        }
        return self::DecryptUsingKeyFile($d,$k);
    }
}
?>