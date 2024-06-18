

#### Kibobo encryption helper based fully on https://github.com/phpseclib/phpseclib, a copy-pasta

#### convert private key to base64
openssl base64 -in key.pem -out key_base64.txt

#### extract private and certificate files from pfx
openssl pkcs12 -in SOURCE.pfx -out key.pem -nocerts -nodes
openssl pkcs12 -in SOURCE.pfx -out cert.pem -nokeys -clcerts


#### Example 
``` php
<?php

require("./RSA.php");
require("./AES.php");
//or 
//require("./crypt.php");


// Example usage
$encryptedKey  = "responseKey";  //responseKey
$encryptedData = "responseData"; //responseData
$privateKey = file_get_contents("./key.pem"); //this is a key.pem private key extracted from pfx

function decryptKey($data, $privateKey){
    $rsa = new RSA();
    $rsa->loadKey($privateKey);
    $rsa->setMGFHash('sha256');
    $rsa->setHash('sha256');
    $rsa->setEncryptionMode(RSA::ENCRYPTION_OAEP);
    return base64_encode($rsa->decrypt(Base64_decode($data)));
}
function decryptData($base64key, $encryptedData)
{
    $aes = new AES(AES::MODE_CBC);
    $key = base64_decode($base64key);
    $iv = substr($key, 0, 16);
    $aes->setKey($key);
    $aes->setIV($iv);
    return $aes->decrypt(base64_decode($encryptedData));
}

$key = decryptKey($encryptedKey, $privateKey);
$output = decryptData($key, $encryptedData);
echo "\n";
echo $key."\n";
echo $output."\n";

?>

````



__It's just a matter of time__
