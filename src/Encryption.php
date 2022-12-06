<?php
namespace OGBitBlt\Cryptography;
use Exception;
use OGBitBlt\Cryptography\DecryptException;
use OGBitBlt\Cryptography\EncryptException;
use OGBitBlt\Cryptography\KeyFileException;
use OGBitBlt\Cryptography\KeyFile;
use OGBitBlt\Cryptography\Decrypt;
use OGBitBlt\Cryptography\Encrypt;
/**
 * The user consumable library object
 * @author Anthony Davis <ogbitblt@pm.me>
 * @package ogbitblt-cryptography
 */
class Encryption
{
    /**
     * Generates a key file used for encrypting and decrypting messages
     * @param int $length The length of the keyfile to create
     * @return string the keyfile 
     */
    public static function GenerateKeyFile(int $length) : string 
    {
        try {
            return KeyFile::GenerateKeyFile($length);
        } catch(KeyFileException $e) {
            self::_logException($e);
            throw $e;
        }
    }
    /**
     * Encrypts a message using the keyfile
     * @param string $message The message to be encrypted
     * @param string $keyfile The keyfile for encrypting the message
     * @return string the encrypted message
     */
    public static function Encrypt(string $message, string $keyfile) : string 
    {
        try {
            return Encrypt::EncryptUsingKeyFile($message, $keyfile);
        } catch(EncryptException $e) {
            self::_logException($e);
            throw $e;
        }
    }
    /**
     * Basically saves the user from making a call to GenerateKeyFile 
     * by wrapping the GenerateKeyFile and Encrypt calls into a single call.
     *
     * @param string the string to be encrypted
     * @return array [
     *      data => "the encrypted string",
     *      keyfile => "the keyfile"
     *      ]
     */
    public static function EncryptAndCreateKeyFile(string $msg) : array 
    {
        try {
            return Encrypt::EncryptyAndCreateKeyFile($msg);
        } catch(EncryptException $e) {
            self::_logException($e);
            throw $e;
        }
    }
    /**
     * 1. encode the string using base64 before encoding (this preserves non-visible characters)
     * 2. then create the keyfile from the base64 encoded string
     * 3. encrypt the base64 encoded string using the keyfile
     * 4. combine the encrypted string with the keyfile into a single string for further obfuscation
     * 4. double compress (gzip) the resulting string 
     * @param string The string to be encrypted
     * @return string The string value...
     *                      ...base64 encoded
     *                      ...encrypted
     *                      ...combined with the keyfile used to encrypt it
     *                      and then double gzipped.
     * Note: This method is not as secure as first creating the keyfile, sending the keyfile to 
     * the party that needs to decrypt the data and then encrypting the data using the keyfile.
     * This method should only be used when sending the keyfile in advance isn't an option. 
     */
    public static function CombinedEncrypt(string $msg) : string 
    {
        try {
            return gzdeflate(
                gzdeflate(
                    Encrypt::EncryptCombined(
                        base64_encode($msg)
                        ),
                    9
                    ),
                9
                );
        } catch(EncryptException $e) {
            self::_logException($e);
            throw $e;
        }
    }
    /**
     * This takes a data packet created by CombinedEncrypt and will Decrypt it.
     * @param string $message The encrypted message to be decrypted
     * @return string The decrypted message
     */
    public static function CombinedDecrypt(string $data) : string 
    {
        try {
            return base64_decode(
                Decrypt::DecryptCombined(
                    gzinflate(
                        gzinflate($data)
                    )
                )
            );
        } catch(DecryptException $e) {
            self::_logException($e);
            throw $e;
        }
    }
    /**
     * Decrypt a message using the keyfile
     * @param string $message The encrypted message to be decrypted
     * @param string $keyfile The keyfile used to decrypt the message
     * @return string The decrypted message
     */
    public static function Decrypt(string $message, string $keyfile) : string 
    {
        try {
            return Decrypt::DecryptUsingKeyFile($message, $keyfile);
        } catch(DecryptException $e) {
            self::_logException($e);
            throw $e;
        }
    }
    /**
     * Logs exception info using the standard php error logging
     * @param \Exception $e
     * @return void
     */
    private static function _logException($e)
    {
        error_log(
            (new \DateTime())
                ->setTimezone(new \DateTimeZone('UTC'))
                ->format('Y/m/d H:i:s') . ' ' . $e
        );
    }
    /**
     * Throws an exception since all methods are static
     */
    public function __construct() 
    {
        throw new Exception("Encryption client cannot be created as a new object.");
    }
}
?>