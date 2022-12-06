<?php
require '../vendor/autoload.php';

use OGBitBlt\Cryptography\Encryption;

$msg = "The earliest known appearance of the phrase was in The Boston Journal. In an article titled \"Current Notes\" in the February 9, 1885, edition, ";
$msg = $msg . "the phrase is mentioned as a good practice sentence for writing students: \"A favorite copy set by writing teachers for their pupils is the ";
$msg = $msg . "following, because it contains every letter of the alphabet: 'A quick brown fox jumps over the lazy dog.'\"[2] Dozens of other newspapers ";
$msg = $msg . "published the phrase over the next few months, all using the version of the sentence starting with \"A\" rather than \"The\". The earliest ";
$msg = $msg . "known use of the phrase starting with \"The\" is from the 1888 book Illustrative Shorthand by Linda Bronson. The modern form (starting with";
$msg = $msg . " \"The\") became more common even though it is slightly longer than the original (starting with \"A\").\n";
$msg = $msg . "A 1908 edition of the Los Angeles Herald Sunday Magazine records that when the New York Herald was equipping an office with typewriters \"a ";
$msg = $msg . "few years ago\", staff found that the common practice sentence of \"now is the time for all good men to come to the aid of the party\" did not";
$msg = $msg . " familiarize typists with the entire alphabet, and ran onto two lines in a newspaper column. They write that a staff member named Arthur F. Curtis";
$msg = $msg . " invented the \"quick brown fox\" pangram to address this.\n";
$msg = $msg . "As the use of typewriters grew in the late 19th century, the phrase began appearing in typing lesson books as a practice sentence. Early examples ";
$msg = $msg . "include How to Become Expert in Typewriting: A Complete Instructor Designed Especially for the Remington Typewriter (1890), and Typewriting ";
$msg = $msg . "Instructor and Stenographer's Hand-book (1892). By the turn of the 20th century, the phrase had become widely known. In the January 10, 1903, ";
$msg = $msg . "issue of Pitman's Phonetic Journal, it is referred to as \"the well known memorized typing line embracing all the letters of the alphabet\". Robert ";
$msg = $msg . "Baden-Powell's book Scouting for Boys (1908) uses the phrase as a practice sentence for signaling.\n";
$msg = $msg . "The first message sent on the Moscow-Washington hotline on August 30, 1963, was the test phrase \"THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG'S BACK ";
$msg = $msg . "1234567890\". Later, during testing, the Russian translators sent a message asking their American counterparts, \"What does it mean when your ";
$msg = $msg . "people say 'The quick brown fox jumped over the lazy dog'?\"\n";
$msg = $msg . "During the 20th century, technicians tested typewriters and teleprinters by typing the sentence.\n";
$msg = $msg . "It is the sentence used in the annual Zaner-Bloser National Handwriting Competition, a cursive writing competition which has been held in the U.S. ";
$msg = $msg . "since 1991.";

/*
 * EXAMPLE 1: Most Secure
 * 
 * Generate a keyfile, this is used to both encrypt and decrypt the data.
 * Send the keyfile to the receiver.
 * 
 * Encrypt the data
 * 
 * Send it to the receiver for them to decrypt.
 */
printf("Sender (Using Keyfile):\n");
printf("Encrypting %d Character Message.\n",strlen($msg));

// base64 encode before encrypting 
// this isn't required, but it will ensure that non-visible characters are encoded correctly
$msg_bytes = base64_encode($msg);
printf("\t=> %d Bytes converted to base64\n",strlen($msg_bytes));

// generate the keyfile
$keyfile = Encryption::GenerateKeyFile(strlen($msg_bytes));
printf("\t=> %d Bytes keyfile\n",strlen($keyfile));

// send the keyfile to the receiver

// encrypt the data using the keyfile
$encrypted = Encryption::Encrypt($msg_bytes, $keyfile);
printf("\t=> %d Bytes encrypted\n",strlen($encrypted));

// i always double compress it, but this is optional
$compressed = gzdeflate($encrypted,9);
printf("\t=> %d Bytes compressed\n", strlen($compressed));


// now send the double compressed file to the receiver
printf("Sent....\n\nReceiver (Using Keyfile):\nUncompressing:\t");
$uncompressed = gzinflate($compressed);
printf("%d Bytes\n",strlen($uncompressed));
$decrypted = Encryption::Decrypt($uncompressed,$keyfile);
printf("Decrypting:\t%d Bytes\nTo ASCII:\t", strlen($decrypted));
$plain_text = base64_decode($decrypted);
printf("%d Bytes\n", strlen($plain_text));
if($plain_text === $msg) printf("\nSuccess: Decrypted message matches original message!\n");
else printf("\nWell darn that didn't work, we expected:\n%s\nBut Got:\n%s\n", $msg, $plain_text);

/*
 * EXAMPLE 2: Less Secure
 * 
 * The Data and the keyfile are combined into a single packet and compressed.
 * No need to use base64 encoding or any kind of compression, the library 
 * does it automagically.
 */
printf("\nSender (Using Combined Keyfile and Data) Less Secure:\n");

// this will automatically base64 encode and gzip
$combined_encrypted = Encryption::CombinedEncrypt($msg);
printf("\t=> %d Bytes encrypted.\n",strlen($combined_encrypted));

printf("Sent...\n\nReceiver (Using Combined Keyfile and Data):\n");

// this will automatially base64 decode and unzip
$combined_decrypted = Encryption::CombinedDecrypt($combined_encrypted);
printf("\t=> %d Bytes decrypted\n",strlen($combined_decrypted));

if($combined_decrypted === $msg) printf("\nSuccess: Decrypted message matches original message!\n");
else printf("\nWell darn that didn't work, we expected:\n%s\nBut Got:\n%s\n", $msg, $combined_decrypted);

?>
