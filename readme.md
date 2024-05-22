

#### Kibobo encryption helper based fully on https://github.com/phpseclib/phpseclib, a copy paste

#### Example 
``` php
<?php
require("./RSA.php");
require("./AES.php");

// Example usage
$encryptedKey  = "responseKey";  //responseKey
$encryptedData = "responseData"; //responseData
$privateKey = file_get_contents("./key.pem");

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
