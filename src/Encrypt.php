<?php
namespace OGBitBlt\Cryptography;

use OGBitBlt\Cryptography\KeyFile;

/**
 * Encrypt Handles encrypting data using the keyfile.
 * @author Anthony Davis <ogbitblt@pm.me>
 * @package ogbitblt-cryptograhy
 */
class Encrypt
{
    /**
     * EncryptWithKeyFile -- Encrypt data
     * @param string $msg The message to be encrypted
     * @param string $kf The keyfile used to encrypt the data
     * @return string the encrypted data
     */
    public static function EncryptUsingKeyFile($msg, $kf) : string 
     {
        $r='';
        if(strlen($msg)>strlen($kf)) 
            for($i=0;$i<=ceil(floatval(strlen($msg)/strlen($kf)));$i++)
                $kf=$kf.$kf;
        
        for($i=0;$i<strlen($msg);$i++)
            $r=$r.KeyFile::_gchs()[
                (
                    array_search(
                        $msg[$i],
                        KeyFile::_gchs(),
                        false
                    ) + 
                    array_search(
                        $kf[$i],
                        KeyFile::_gchs(),
                        false
                    )
                ) % count(KeyFile::_gchs())
            ];
        return $r;
    }

    /**
     * EncryptAndCreateKeyFile -- Encrypts data and generates
     * a keyfile that can be used to decrypt the data.
     * @param string $msg the data to be encrypted.
     * @return associated array keyfile & data respectively.
     */
    public static function EncryptyAndCreateKeyFile($msg) : array 
    {
        $kf=KeyFile::GenerateKeyFile(strlen($msg));
        $msg = self::EncryptUsingKeyFile($msg, $kf);
        return ['keyfile' => $kf, 'data' => $msg];
    }

    /**
     * EncryptCombined -- 
     * It's not recommended that this is used since it's not secure to 
     * provide the passkey along with the encrypted data. But if you want
     * a simple encrypted packet that doesn't require that the passkey is
     * passed to the reciever ahead of time then you can use this function.
     * @param string $msg - The data to be encrypted
     */
    public static function EncryptCombined($msg) : string
    {
        $r='';
        $a = self::EncryptyAndCreateKeyFile($msg);
        for($i=0;$i<strlen($a['keyfile']);$i++){
            $r = $r.$a['keyfile'][$i].$a['data'][$i];
        }
        return $r;
    }
}
?>
