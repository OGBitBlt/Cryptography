<?php
namespace OGBitBlt\Cryptography;

use Exception;
use Throwable;

class KeyFileException extends Exception {
    public function __construct(string $message, int $code = 0, Throwable $prev = null) {
        parent::__construct($message,$code,$prev);
    }
}
?>