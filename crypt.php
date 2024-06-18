<?php


/**
 * Pure-PHP implementation of AES.
 *
 * Uses mcrypt, if available/possible, and an internal implementation, otherwise.
 *
 * PHP version 5
 *
 * NOTE: Since AES.php is (for compatibility and phpseclib-historical reasons) virtually
 * just a wrapper to Rijndael.php you may consider using Rijndael.php instead of
 * to save one include_once().
 *
 * If {@link self::setKeyLength() setKeyLength()} isn't called, it'll be calculated from
 * {@link self::setKey() setKey()}.  ie. if the key is 128-bits, the key length will be 128-bits.  If it's 136-bits
 * it'll be null-padded to 192-bits and 192 bits will be the key length until {@link self::setKey() setKey()}
 * is called, again, at which point, it'll be recalculated.
 *
 * Since \phpseclib\Crypt\AES extends \phpseclib\Crypt\Rijndael, some functions are available to be called that, in the context of AES, don't
 * make a whole lot of sense.  {@link self::setBlockLength() setBlockLength()}, for instance.  Calling that function,
 * however possible, won't do anything (AES has a fixed block length whereas Rijndael has a variable one).
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $aes = new \phpseclib\Crypt\AES();
 *
 *    $aes->setKey('abcdefghijklmnop');
 *
 *    $size = 10 * 1024;
 *    $plaintext = '';
 *    for ($i = 0; $i < $size; $i++) {
 *        $plaintext.= 'a';
 *    }
 *
 *    echo $aes->decrypt($aes->encrypt($plaintext));
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   AES
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2008 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

/**
 * Pure-PHP implementation of AES.
 *
 * @package AES
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class KiboboCryptAES extends KiboboCryptRijndael
{
    /**
     * Dummy function
     *
     * Since \phpseclib\Crypt\AES extends \phpseclib\Crypt\Rijndael, this function is, technically, available, but it doesn't do anything.
     *
     * @see \phpseclib\Crypt\Rijndael::setBlockLength()
     * @access public
     * @param int $length
     */
    function setBlockLength($length)
    {
        return;
    }

    /**
     * Sets the key length
     *
     * Valid key lengths are 128, 192, and 256.  If the length is less than 128, it will be rounded up to
     * 128.  If the length is greater than 128 and invalid, it will be rounded down to the closest valid amount.
     *
     * @see \phpseclib\Crypt\Rijndael:setKeyLength()
     * @access public
     * @param int $length
     */
    function setKeyLength($length)
    {
        switch ($length) {
            case 160:
                $length = 192;
                break;
            case 224:
                $length = 256;
        }
        parent::setKeyLength($length);
    }

    /**
     * Sets the key.
     *
     * Rijndael supports five different key lengths, AES only supports three.
     *
     * @see \phpseclib\Crypt\Rijndael:setKey()
     * @see setKeyLength()
     * @access public
     * @param string $key
     */
    function setKey($key)
    {
        parent::setKey($key);

        if (!$this->explicit_key_length) {
            $length = strlen($key);
            switch (true) {
                case $length <= 16:
                    $this->key_length = 16;
                    break;
                case $length <= 24:
                    $this->key_length = 24;
                    break;
                default:
                    $this->key_length = 32;
            }
            $this->_setEngine();
        }
    }
}


/**
 * Base Class for all \phpseclib\Crypt\* cipher classes
 *
 * PHP version 5
 *
 * Internally for phpseclib developers:
 *  If you plan to add a new cipher class, please note following rules:
 *
 *  - The new \phpseclib\Crypt\* cipher class should extend \phpseclib\Crypt\Base
 *
 *  - Following methods are then required to be overridden/overloaded:
 *
 *    - _encryptBlock()
 *
 *    - _decryptBlock()
 *
 *    - _setupKey()
 *
 *  - All other methods are optional to be overridden/overloaded
 *
 *  - Look at the source code of the current ciphers how they extend \phpseclib\Crypt\Base
 *    and take one of them as a start up for the new cipher class.
 *
 *  - Please read all the other comments/notes/hints here also for each class var/method
 *
 * @category  Crypt
 * @package   Base
 * @author    Jim Wigginton <terrafrost@php.net>
 * @author    Hans-Juergen Petrich <petrich@tronic-media.com>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */


/**
 * Base Class for all \phpseclib\Crypt\* cipher classes
 *
 * @package Base
 * @author  Jim Wigginton <terrafrost@php.net>
 * @author  Hans-Juergen Petrich <petrich@tronic-media.com>
 */
abstract class KiboboCryptBase
{
    /**#@+
     * @access public
     * @see \phpseclib\Crypt\Base::encrypt()
     * @see \phpseclib\Crypt\Base::decrypt()
     */
    /**
     * Encrypt / decrypt using the Counter mode.
     *
     * Set to -1 since that's what Crypt/Random.php uses to index the CTR mode.
     *
     * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
     */
    const MODE_CTR = -1;
    /**
     * Encrypt / decrypt using the Electronic Code Book mode.
     *
     * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29
     */
    const MODE_ECB = 1;
    /**
     * Encrypt / decrypt using the Code Book Chaining mode.
     *
     * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
     */
    const MODE_CBC = 2;
    /**
     * Encrypt / decrypt using the Cipher Feedback mode.
     *
     * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
     */
    const MODE_CFB = 3;
    /**
     * Encrypt / decrypt using the Cipher Feedback mode (8bit)
     */
    const MODE_CFB8 = 6;
    /**
     * Encrypt / decrypt using the Output Feedback mode (8bit)
     */
    const MODE_OFB8 = 7;
    /**
     * Encrypt / decrypt using the Output Feedback mode.
     *
     * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29
     */
    const MODE_OFB = 4;
    /**
     * Encrypt / decrypt using streaming mode.
     */
    const MODE_STREAM = 5;
    /**#@-*/

    /**
     * Whirlpool available flag
     *
     * @see \phpseclib\Crypt\Base::_hashInlineCryptFunction()
     * @var bool
     * @access private
     */
    static $WHIRLPOOL_AVAILABLE;

    /**#@+
     * @access private
     * @see \phpseclib\Crypt\Base::__construct()
     */
    /**
     * Base value for the internal implementation $engine switch
     */
    const ENGINE_INTERNAL = 1;
    /**
     * Base value for the mcrypt implementation $engine switch
     */
    const ENGINE_MCRYPT = 2;
    /**
     * Base value for the mcrypt implementation $engine switch
     */
    const ENGINE_OPENSSL = 3;
    /**#@-*/

    /**
     * The Encryption Mode
     *
     * @see self::__construct()
     * @var int
     * @access private
     */
    var $mode;

    /**
     * The Block Length of the block cipher
     *
     * @var int
     * @access private
     */
    var $block_size = 16;

    /**
     * The Key
     *
     * @see self::setKey()
     * @var string
     * @access private
     */
    var $key = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    /**
     * The Initialization Vector
     *
     * @see self::setIV()
     * @var string
     * @access private
     */
    var $iv = '';

    /**
     * A "sliding" Initialization Vector
     *
     * @see self::enableContinuousBuffer()
     * @see self::_clearBuffers()
     * @var string
     * @access private
     */
    var $encryptIV;

    /**
     * A "sliding" Initialization Vector
     *
     * @see self::enableContinuousBuffer()
     * @see self::_clearBuffers()
     * @var string
     * @access private
     */
    var $decryptIV;

    /**
     * Continuous Buffer status
     *
     * @see self::enableContinuousBuffer()
     * @var bool
     * @access private
     */
    var $continuousBuffer = false;

    /**
     * Encryption buffer for CTR, OFB and CFB modes
     *
     * @see self::encrypt()
     * @see self::_clearBuffers()
     * @var array
     * @access private
     */
    var $enbuffer;

    /**
     * Decryption buffer for CTR, OFB and CFB modes
     *
     * @see self::decrypt()
     * @see self::_clearBuffers()
     * @var array
     * @access private
     */
    var $debuffer;

    /**
     * mcrypt resource for encryption
     *
     * The mcrypt resource can be recreated every time something needs to be created or it can be created just once.
     * Since mcrypt operates in continuous mode, by default, it'll need to be recreated when in non-continuous mode.
     *
     * @see self::encrypt()
     * @var resource
     * @access private
     */
    var $enmcrypt;

    /**
     * mcrypt resource for decryption
     *
     * The mcrypt resource can be recreated every time something needs to be created or it can be created just once.
     * Since mcrypt operates in continuous mode, by default, it'll need to be recreated when in non-continuous mode.
     *
     * @see self::decrypt()
     * @var resource
     * @access private
     */
    var $demcrypt;

    /**
     * Does the enmcrypt resource need to be (re)initialized?
     *
     * @see \phpseclib\Crypt\Twofish::setKey()
     * @see \phpseclib\Crypt\Twofish::setIV()
     * @var bool
     * @access private
     */
    var $enchanged = true;

    /**
     * Does the demcrypt resource need to be (re)initialized?
     *
     * @see \phpseclib\Crypt\Twofish::setKey()
     * @see \phpseclib\Crypt\Twofish::setIV()
     * @var bool
     * @access private
     */
    var $dechanged = true;

    /**
     * mcrypt resource for CFB mode
     *
     * mcrypt's CFB mode, in (and only in) buffered context,
     * is broken, so phpseclib implements the CFB mode by it self,
     * even when the mcrypt php extension is available.
     *
     * In order to do the CFB-mode work (fast) phpseclib
     * use a separate ECB-mode mcrypt resource.
     *
     * @link http://phpseclib.sourceforge.net/cfb-demo.phps
     * @see self::encrypt()
     * @see self::decrypt()
     * @see self::_setupMcrypt()
     * @var resource
     * @access private
     */
    var $ecb;

    /**
     * Optimizing value while CFB-encrypting
     *
     * Only relevant if $continuousBuffer enabled
     * and $engine == self::ENGINE_MCRYPT
     *
     * It's faster to re-init $enmcrypt if
     * $buffer bytes > $cfb_init_len than
     * using the $ecb resource furthermore.
     *
     * This value depends of the chosen cipher
     * and the time it would be needed for it's
     * initialization [by mcrypt_generic_init()]
     * which, typically, depends on the complexity
     * on its internaly Key-expanding algorithm.
     *
     * @see self::encrypt()
     * @var int
     * @access private
     */
    var $cfb_init_len = 600;

    /**
     * Does internal cipher state need to be (re)initialized?
     *
     * @see self::setKey()
     * @see self::setIV()
     * @see self::disableContinuousBuffer()
     * @var bool
     * @access private
     */
    var $changed = true;

    /**
     * Padding status
     *
     * @see self::enablePadding()
     * @var bool
     * @access private
     */
    var $padding = true;

    /**
     * Is the mode one that is paddable?
     *
     * @see self::__construct()
     * @var bool
     * @access private
     */
    var $paddable = false;

    /**
     * Holds which crypt engine internaly should be use,
     * which will be determined automatically on __construct()
     *
     * Currently available $engines are:
     * - self::ENGINE_OPENSSL  (very fast, php-extension: openssl, extension_loaded('openssl') required)
     * - self::ENGINE_MCRYPT   (fast, php-extension: mcrypt, extension_loaded('mcrypt') required)
     * - self::ENGINE_INTERNAL (slower, pure php-engine, no php-extension required)
     *
     * @see self::_setEngine()
     * @see self::encrypt()
     * @see self::decrypt()
     * @var int
     * @access private
     */
    var $engine;

    /**
     * Holds the preferred crypt engine
     *
     * @see self::_setEngine()
     * @see self::setPreferredEngine()
     * @var int
     * @access private
     */
    var $preferredEngine;

    /**
     * The mcrypt specific name of the cipher
     *
     * Only used if $engine == self::ENGINE_MCRYPT
     *
     * @link http://www.php.net/mcrypt_module_open
     * @link http://www.php.net/mcrypt_list_algorithms
     * @see self::_setupMcrypt()
     * @var string
     * @access private
     */
    var $cipher_name_mcrypt;

    /**
     * The openssl specific name of the cipher
     *
     * Only used if $engine == self::ENGINE_OPENSSL
     *
     * @link http://www.php.net/openssl-get-cipher-methods
     * @var string
     * @access private
     */
    var $cipher_name_openssl;

    /**
     * The openssl specific name of the cipher in ECB mode
     *
     * If OpenSSL does not support the mode we're trying to use (CTR)
     * it can still be emulated with ECB mode.
     *
     * @link http://www.php.net/openssl-get-cipher-methods
     * @var string
     * @access private
     */
    var $cipher_name_openssl_ecb;

    /**
     * The default salt used by setPassword()
     *
     * @see self::setPassword()
     * @var string
     * @access private
     */
    var $password_default_salt = 'phpseclib/salt';

    /**
     * The name of the performance-optimized callback function
     *
     * Used by encrypt() / decrypt()
     * only if $engine == self::ENGINE_INTERNAL
     *
     * @see self::encrypt()
     * @see self::decrypt()
     * @see self::_setupInlineCrypt()
     * @see self::$use_inline_crypt
     * @var Callback
     * @access private
     */
    var $inline_crypt;

    /**
     * Holds whether performance-optimized $inline_crypt() can/should be used.
     *
     * @see self::encrypt()
     * @see self::decrypt()
     * @see self::inline_crypt
     * @var mixed
     * @access private
     */
    var $use_inline_crypt = true;

    /**
     * If OpenSSL can be used in ECB but not in CTR we can emulate CTR
     *
     * @see self::_openssl_ctr_process()
     * @var bool
     * @access private
     */
    var $openssl_emulate_ctr = false;

    /**
     * Determines what options are passed to openssl_encrypt/decrypt
     *
     * @see self::isValidEngine()
     * @var mixed
     * @access private
     */
    var $openssl_options;

    /**
     * Has the key length explicitly been set or should it be derived from the key, itself?
     *
     * @see self::setKeyLength()
     * @var bool
     * @access private
     */
    var $explicit_key_length = false;

    /**
     * Don't truncate / null pad key
     *
     * @see self::_clearBuffers()
     * @var bool
     * @access private
     */
    var $skip_key_adjustment = false;

    /**
     * Default Constructor.
     *
     * Determines whether or not the mcrypt extension should be used.
     *
     * $mode could be:
     *
     * - self::MODE_ECB
     *
     * - self::MODE_CBC
     *
     * - self::MODE_CTR
     *
     * - self::MODE_CFB
     *
     * - self::MODE_OFB
     *
     * If not explicitly set, self::MODE_CBC will be used.
     *
     * @param int $mode
     * @access public
     */
    function __construct($mode = self::MODE_CBC)
    {
        // $mode dependent settings
        switch ($mode) {
            case self::MODE_ECB:
                $this->paddable = true;
                $this->mode = self::MODE_ECB;
                break;
            case self::MODE_CTR:
            case self::MODE_CFB:
            case self::MODE_CFB8:
            case self::MODE_OFB8:
            case self::MODE_OFB:
            case self::MODE_STREAM:
                $this->mode = $mode;
                break;
            case self::MODE_CBC:
            default:
                $this->paddable = true;
                $this->mode = self::MODE_CBC;
        }

        $this->_setEngine();

        // Determining whether inline crypting can be used by the cipher
        if ($this->use_inline_crypt !== false) {
            $this->use_inline_crypt = version_compare(PHP_VERSION, '5.3.0') >= 0 || function_exists('create_function');
        }

        if (!defined('PHP_INT_SIZE')) {
            define('PHP_INT_SIZE', 4);
        }

        if (!defined('CRYPT_BASE_USE_REG_INTVAL')) {
            switch (true) {
                // PHP_OS & "\xDF\xDF\xDF" == strtoupper(substr(PHP_OS, 0, 3)), but a lot faster
                case (PHP_OS & "\xDF\xDF\xDF") === 'WIN':
                case (php_uname('m') & "\xDF\xDF\xDF") != 'ARM':
                case PHP_INT_SIZE == 8:
                    define('CRYPT_BASE_USE_REG_INTVAL', true);
                    break;
                case (php_uname('m') & "\xDF\xDF\xDF") == 'ARM':
                    switch (true) {
                        /* PHP 7.0.0 introduced a bug that affected 32-bit ARM processors:

                           https://github.com/php/php-src/commit/716da71446ebbd40fa6cf2cea8a4b70f504cc3cd

                           altho the changelogs make no mention of it, this bug was fixed with this commit:

                           https://github.com/php/php-src/commit/c1729272b17a1fe893d1a54e423d3b71470f3ee8

                           affected versions of PHP are: 7.0.x, 7.1.0 - 7.1.23 and 7.2.0 - 7.2.11 */
                        case PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70123:
                        case PHP_VERSION_ID >= 70200 && PHP_VERSION_ID <= 70211:
                            define('CRYPT_BASE_USE_REG_INTVAL', false);
                            break;
                        default:
                            define('CRYPT_BASE_USE_REG_INTVAL', true);
                    }
            }
        }
    }

    /**
     * Sets the initialization vector. (optional)
     *
     * SetIV is not required when self::MODE_ECB (or ie for AES: \phpseclib\Crypt\AES::MODE_ECB) is being used.  If not explicitly set, it'll be assumed
     * to be all zero's.
     *
     * @access public
     * @param string $iv
     * @internal Can be overwritten by a sub class, but does not have to be
     */
    function setIV($iv)
    {
        if ($this->mode == self::MODE_ECB) {
            return;
        }

        $this->iv = $iv;
        $this->changed = true;
    }

    /**
     * Sets the key length.
     *
     * Keys with explicitly set lengths need to be treated accordingly
     *
     * @access public
     * @param int $length
     */
    function setKeyLength($length)
    {
        $this->explicit_key_length = true;
        $this->changed = true;
        $this->_setEngine();
    }

    /**
     * Returns the current key length in bits
     *
     * @access public
     * @return int
     */
    function getKeyLength()
    {
        return $this->key_length << 3;
    }

    /**
     * Returns the current block length in bits
     *
     * @access public
     * @return int
     */
    function getBlockLength()
    {
        return $this->block_size << 3;
    }

    /**
     * Sets the key.
     *
     * The min/max length(s) of the key depends on the cipher which is used.
     * If the key not fits the length(s) of the cipher it will paded with null bytes
     * up to the closest valid key length.  If the key is more than max length,
     * we trim the excess bits.
     *
     * If the key is not explicitly set, it'll be assumed to be all null bytes.
     *
     * @access public
     * @param string $key
     * @internal Could, but not must, extend by the child Crypt_* class
     */
    function setKey($key)
    {
        if (!$this->explicit_key_length) {
            $this->setKeyLength(strlen($key) << 3);
            $this->explicit_key_length = false;
        }

        $this->key = $key;
        $this->changed = true;
        $this->_setEngine();
    }

    /**
     * Sets the password.
     *
     * Depending on what $method is set to, setPassword()'s (optional) parameters are as follows:
     *     {@link http://en.wikipedia.org/wiki/PBKDF2 pbkdf2} or pbkdf1:
     *         $hash, $salt, $count, $dkLen
     *
     *         Where $hash (default = sha1) currently supports the following hashes: see: Crypt/Hash.php
     *     {@link https://en.wikipedia.org/wiki/Bcrypt bcypt}:
     *         $salt, $rounds, $keylen
     *
     *         This is a modified version of bcrypt used by OpenSSH.
     *
     * @see Crypt/Hash.php
     * @param string $password
     * @param string $method
     * @return bool
     * @access public
     * @internal Could, but not must, extend by the child Crypt_* class
     */
    function setPassword($password, $method = 'pbkdf2')
    {
        $key = '';

        switch ($method) {
            case 'bcrypt':
                $func_args = func_get_args();

                if (!isset($func_args[2])) {
                    return false;
                }

                $salt = $func_args[2];

                $rounds = isset($func_args[3]) ? $func_args[3] : 16;
                $keylen = isset($func_args[4]) ? $func_args[4] : $this->key_length;

                $bf = new Blowfish();
                $key = $bf->bcrypt_pbkdf($password, $salt, $keylen + $this->block_size, $rounds);
                if (!$key) {
                    return false;
                }

                $this->setKey(substr($key, 0, $keylen));
                $this->setIV(substr($key, $keylen));

                return true;
            default: // 'pbkdf2' or 'pbkdf1'
                $func_args = func_get_args();

                // Hash function
                $hash = isset($func_args[2]) ? $func_args[2] : 'sha1';

                // WPA and WPA2 use the SSID as the salt
                $salt = isset($func_args[3]) ? $func_args[3] : $this->password_default_salt;

                // RFC2898#section-4.2 uses 1,000 iterations by default
                // WPA and WPA2 use 4,096.
                $count = isset($func_args[4]) ? $func_args[4] : 1000;

                // Keylength
                if (isset($func_args[5])) {
                    $dkLen = $func_args[5];
                } else {
                    $dkLen = $method == 'pbkdf1' ? 2 * $this->key_length : $this->key_length;
                }

                switch (true) {
                    case $method == 'pbkdf1':
                        $hashObj = new KiboboCryptHash();
                        $hashObj->setHash($hash);
                        if ($dkLen > $hashObj->getLength()) {
                            user_error('Derived key too long');
                            return false;
                        }
                        $t = $password . $salt;
                        for ($i = 0; $i < $count; ++$i) {
                            $t = $hashObj->hash($t);
                        }
                        $key = substr($t, 0, $dkLen);

                        $this->setKey(substr($key, 0, $dkLen >> 1));
                        $this->setIV(substr($key, $dkLen >> 1));

                        return true;
                    // Determining if php[>=5.5.0]'s hash_pbkdf2() function avail- and useable
                    case !function_exists('hash_pbkdf2'):
                    case !function_exists('hash_algos'):
                    case !in_array($hash, hash_algos()):
                        $i = 1;
                        $hmac = new KiboboCryptHash();
                        $hmac->setHash($hash);
                        $hmac->setKey($password);
                        while (strlen($key) < $dkLen) {
                            $f = $u = $hmac->hash($salt . pack('N', $i++));
                            for ($j = 2; $j <= $count; ++$j) {
                                $u = $hmac->hash($u);
                                $f^= $u;
                            }
                            $key.= $f;
                        }
                        $key = substr($key, 0, $dkLen);
                        break;
                    default:
                        $key = hash_pbkdf2($hash, $password, $salt, $count, $dkLen, true);
                }
        }

        $this->setKey($key);

        return true;
    }

    /**
     * Encrypts a message.
     *
     * $plaintext will be padded with additional bytes such that it's length is a multiple of the block size. Other cipher
     * implementations may or may not pad in the same manner.  Other common approaches to padding and the reasons why it's
     * necessary are discussed in the following
     * URL:
     *
     * {@link http://www.di-mgt.com.au/cryptopad.html http://www.di-mgt.com.au/cryptopad.html}
     *
     * An alternative to padding is to, separately, send the length of the file.  This is what SSH, in fact, does.
     * strlen($plaintext) will still need to be a multiple of the block size, however, arbitrary values can be added to make it that
     * length.
     *
     * @see self::decrypt()
     * @access public
     * @param string $plaintext
     * @return string $ciphertext
     * @internal Could, but not must, extend by the child Crypt_* class
     */
    function encrypt($plaintext)
    {
        if ($this->paddable) {
            $plaintext = $this->_pad($plaintext);
        }

        if ($this->engine === self::ENGINE_OPENSSL) {
            if ($this->changed) {
                $this->_clearBuffers();
                $this->changed = false;
            }
            switch ($this->mode) {
                case self::MODE_STREAM:
                    return openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, $this->openssl_options);
                case self::MODE_ECB:
                    $result = @openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, $this->openssl_options);
                    return !defined('OPENSSL_RAW_DATA') ? substr($result, 0, -$this->block_size) : $result;
                case self::MODE_CBC:
                    $result = openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, $this->openssl_options, $this->encryptIV);
                    if (!defined('OPENSSL_RAW_DATA')) {
                        $result = substr($result, 0, -$this->block_size);
                    }
                    if ($this->continuousBuffer) {
                        $this->encryptIV = substr($result, -$this->block_size);
                    }
                    return $result;
                case self::MODE_CTR:
                    return $this->_openssl_ctr_process($plaintext, $this->encryptIV, $this->enbuffer);
                case self::MODE_CFB:
                    // cfb loosely routines inspired by openssl's:
                    // {@link http://cvs.openssl.org/fileview?f=openssl/crypto/modes/cfb128.c&v=1.3.2.2.2.1}
                    $ciphertext = '';
                    if ($this->continuousBuffer) {
                        $iv = &$this->encryptIV;
                        $pos = &$this->enbuffer['pos'];
                    } else {
                        $iv = $this->encryptIV;
                        $pos = 0;
                    }
                    $len = strlen($plaintext);
                    $i = 0;
                    if ($pos) {
                        $orig_pos = $pos;
                        $max = $this->block_size - $pos;
                        if ($len >= $max) {
                            $i = $max;
                            $len-= $max;
                            $pos = 0;
                        } else {
                            $i = $len;
                            $pos+= $len;
                            $len = 0;
                        }
                        // ie. $i = min($max, $len), $len-= $i, $pos+= $i, $pos%= $blocksize
                        $ciphertext = substr($iv, $orig_pos) ^ $plaintext;
                        $iv = substr_replace($iv, $ciphertext, $orig_pos, $i);
                        $plaintext = substr($plaintext, $i);
                    }

                    $overflow = $len % $this->block_size;

                    if ($overflow) {
                        $ciphertext.= openssl_encrypt(substr($plaintext, 0, -$overflow) . str_repeat("\0", $this->block_size), $this->cipher_name_openssl, $this->key, $this->openssl_options, $iv);
                        $iv = $this->_string_pop($ciphertext, $this->block_size);

                        $size = $len - $overflow;
                        $block = $iv ^ substr($plaintext, -$overflow);
                        $iv = substr_replace($iv, $block, 0, $overflow);
                        $ciphertext.= $block;
                        $pos = $overflow;
                    } elseif ($len) {
                        $ciphertext = openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, $this->openssl_options, $iv);
                        $iv = substr($ciphertext, -$this->block_size);
                    }

                    return $ciphertext;
                case self::MODE_CFB8:
                    $ciphertext = openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, $this->openssl_options, $this->encryptIV);
                    if ($this->continuousBuffer) {
                        if (($len = strlen($ciphertext)) >= $this->block_size) {
                            $this->encryptIV = substr($ciphertext, -$this->block_size);
                        } else {
                            $this->encryptIV = substr($this->encryptIV, $len - $this->block_size) . substr($ciphertext, -$len);
                        }
                    }
                    return $ciphertext;
                case self::MODE_OFB8:
                    // OpenSSL has built in support for cfb8 but not ofb8
                    $ciphertext = '';
                    $len = strlen($plaintext);
                    $iv = $this->encryptIV;

                    for ($i = 0; $i < $len; ++$i) {
                        $xor = openssl_encrypt($iv, $this->cipher_name_openssl_ecb, $this->key, $this->openssl_options, $this->decryptIV);
                        $ciphertext.= $plaintext[$i] ^ $xor;
                        $iv = substr($iv, 1) . $xor[0];
                    }

                    if ($this->continuousBuffer) {
                        $this->encryptIV = $iv;
                    }
                    break;
                case self::MODE_OFB:
                    return $this->_openssl_ofb_process($plaintext, $this->encryptIV, $this->enbuffer);
            }
        }

        if ($this->engine === self::ENGINE_MCRYPT) {
            set_error_handler(array($this, 'do_nothing'));

            if ($this->changed) {
                $this->_setupMcrypt();
                $this->changed = false;
            }
            if ($this->enchanged) {
                mcrypt_generic_init($this->enmcrypt, $this->key, $this->encryptIV);
                $this->enchanged = false;
            }

            // re: {@link http://phpseclib.sourceforge.net/cfb-demo.phps}
            // using mcrypt's default handing of CFB the above would output two different things.  using phpseclib's
            // rewritten CFB implementation the above outputs the same thing twice.
            if ($this->mode == self::MODE_CFB && $this->continuousBuffer) {
                $block_size = $this->block_size;
                $iv = &$this->encryptIV;
                $pos = &$this->enbuffer['pos'];
                $len = strlen($plaintext);
                $ciphertext = '';
                $i = 0;
                if ($pos) {
                    $orig_pos = $pos;
                    $max = $block_size - $pos;
                    if ($len >= $max) {
                        $i = $max;
                        $len-= $max;
                        $pos = 0;
                    } else {
                        $i = $len;
                        $pos+= $len;
                        $len = 0;
                    }
                    $ciphertext = substr($iv, $orig_pos) ^ $plaintext;
                    $iv = substr_replace($iv, $ciphertext, $orig_pos, $i);
                    $this->enbuffer['enmcrypt_init'] = true;
                }
                if ($len >= $block_size) {
                    if ($this->enbuffer['enmcrypt_init'] === false || $len > $this->cfb_init_len) {
                        if ($this->enbuffer['enmcrypt_init'] === true) {
                            mcrypt_generic_init($this->enmcrypt, $this->key, $iv);
                            $this->enbuffer['enmcrypt_init'] = false;
                        }
                        $ciphertext.= mcrypt_generic($this->enmcrypt, substr($plaintext, $i, $len - $len % $block_size));
                        $iv = substr($ciphertext, -$block_size);
                        $len%= $block_size;
                    } else {
                        while ($len >= $block_size) {
                            $iv = mcrypt_generic($this->ecb, $iv) ^ substr($plaintext, $i, $block_size);
                            $ciphertext.= $iv;
                            $len-= $block_size;
                            $i+= $block_size;
                        }
                    }
                }

                if ($len) {
                    $iv = mcrypt_generic($this->ecb, $iv);
                    $block = $iv ^ substr($plaintext, -$len);
                    $iv = substr_replace($iv, $block, 0, $len);
                    $ciphertext.= $block;
                    $pos = $len;
                }

                restore_error_handler();

                return $ciphertext;
            }

            $ciphertext = mcrypt_generic($this->enmcrypt, $plaintext);

            if (!$this->continuousBuffer) {
                mcrypt_generic_init($this->enmcrypt, $this->key, $this->encryptIV);
            }

            restore_error_handler();

            return $ciphertext;
        }

        if ($this->changed) {
            $this->_setup();
            $this->changed = false;
        }
        if ($this->use_inline_crypt) {
            $inline = $this->inline_crypt;
            return $inline('encrypt', $this, $plaintext);
        }

        $buffer = &$this->enbuffer;
        $block_size = $this->block_size;
        $ciphertext = '';
        switch ($this->mode) {
            case self::MODE_ECB:
                for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                    $ciphertext.= $this->_encryptBlock(substr($plaintext, $i, $block_size));
                }
                break;
            case self::MODE_CBC:
                $xor = $this->encryptIV;
                for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                    $block = substr($plaintext, $i, $block_size);
                    $block = $this->_encryptBlock($block ^ $xor);
                    $xor = $block;
                    $ciphertext.= $block;
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                }
                break;
            case self::MODE_CTR:
                $xor = $this->encryptIV;
                if (strlen($buffer['ciphertext'])) {
                    for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                        $block = substr($plaintext, $i, $block_size);
                        if (strlen($block) > strlen($buffer['ciphertext'])) {
                            $buffer['ciphertext'].= $this->_encryptBlock($xor);
                            $this->_increment_str($xor);
                        }
                        $key = $this->_string_shift($buffer['ciphertext'], $block_size);
                        $ciphertext.= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                        $block = substr($plaintext, $i, $block_size);
                        $key = $this->_encryptBlock($xor);
                        $this->_increment_str($xor);
                        $ciphertext.= $block ^ $key;
                    }
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                    if ($start = strlen($plaintext) % $block_size) {
                        $buffer['ciphertext'] = substr($key, $start) . $buffer['ciphertext'];
                    }
                }
                break;
            case self::MODE_CFB:
                // cfb loosely routines inspired by openssl's:
                // {@link http://cvs.openssl.org/fileview?f=openssl/crypto/modes/cfb128.c&v=1.3.2.2.2.1}
                if ($this->continuousBuffer) {
                    $iv = &$this->encryptIV;
                    $pos = &$buffer['pos'];
                } else {
                    $iv = $this->encryptIV;
                    $pos = 0;
                }
                $len = strlen($plaintext);
                $i = 0;
                if ($pos) {
                    $orig_pos = $pos;
                    $max = $block_size - $pos;
                    if ($len >= $max) {
                        $i = $max;
                        $len-= $max;
                        $pos = 0;
                    } else {
                        $i = $len;
                        $pos+= $len;
                        $len = 0;
                    }
                    // ie. $i = min($max, $len), $len-= $i, $pos+= $i, $pos%= $blocksize
                    $ciphertext = substr($iv, $orig_pos) ^ $plaintext;
                    $iv = substr_replace($iv, $ciphertext, $orig_pos, $i);
                }
                while ($len >= $block_size) {
                    $iv = $this->_encryptBlock($iv) ^ substr($plaintext, $i, $block_size);
                    $ciphertext.= $iv;
                    $len-= $block_size;
                    $i+= $block_size;
                }
                if ($len) {
                    $iv = $this->_encryptBlock($iv);
                    $block = $iv ^ substr($plaintext, $i);
                    $iv = substr_replace($iv, $block, 0, $len);
                    $ciphertext.= $block;
                    $pos = $len;
                }
                break;
            case self::MODE_CFB8:
                // compared to regular CFB, which encrypts a block at a time,
                // here, we're encrypting a byte at a time
                $ciphertext = '';
                $len = strlen($plaintext);
                $iv = $this->encryptIV;

                for ($i = 0; $i < $len; ++$i) {
                    $ciphertext.= ($c = $plaintext[$i] ^ $this->_encryptBlock($iv));
                    $iv = substr($iv, 1) . $c;
                }

                if ($this->continuousBuffer) {
                    if ($len >= $block_size) {
                        $this->encryptIV = substr($ciphertext, -$block_size);
                    } else {
                        $this->encryptIV = substr($this->encryptIV, $len - $block_size) . substr($ciphertext, -$len);
                    }
                }
                break;
            case self::MODE_OFB8:
                $ciphertext = '';
                $len = strlen($plaintext);
                $iv = $this->encryptIV;

                for ($i = 0; $i < $len; ++$i) {
                    $xor = $this->_encryptBlock($iv);
                    $ciphertext.= $plaintext[$i] ^ $xor;
                    $iv = substr($iv, 1) . $xor[0];
                }

                if ($this->continuousBuffer) {
                    $this->encryptIV = $iv;
                }
                break;
            case self::MODE_OFB:
                $xor = $this->encryptIV;
                if (strlen($buffer['xor'])) {
                    for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                        $block = substr($plaintext, $i, $block_size);
                        if (strlen($block) > strlen($buffer['xor'])) {
                            $xor = $this->_encryptBlock($xor);
                            $buffer['xor'].= $xor;
                        }
                        $key = $this->_string_shift($buffer['xor'], $block_size);
                        $ciphertext.= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                        $xor = $this->_encryptBlock($xor);
                        $ciphertext.= substr($plaintext, $i, $block_size) ^ $xor;
                    }
                    $key = $xor;
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                    if ($start = strlen($plaintext) % $block_size) {
                        $buffer['xor'] = substr($key, $start) . $buffer['xor'];
                    }
                }
                break;
            case self::MODE_STREAM:
                $ciphertext = $this->_encryptBlock($plaintext);
                break;
        }

        return $ciphertext;
    }

    /**
     * Decrypts a message.
     *
     * If strlen($ciphertext) is not a multiple of the block size, null bytes will be added to the end of the string until
     * it is.
     *
     * @see self::encrypt()
     * @access public
     * @param string $ciphertext
     * @return string $plaintext
     * @internal Could, but not must, extend by the child Crypt_* class
     */
    function decrypt($ciphertext)
    {
        if ($this->paddable) {
            // we pad with chr(0) since that's what mcrypt_generic does.  to quote from {@link http://www.php.net/function.mcrypt-generic}:
            // "The data is padded with "\0" to make sure the length of the data is n * blocksize."
            $ciphertext = str_pad($ciphertext, strlen($ciphertext) + ($this->block_size - strlen($ciphertext) % $this->block_size) % $this->block_size, chr(0));
        }

        if ($this->engine === self::ENGINE_OPENSSL) {
            if ($this->changed) {
                $this->_clearBuffers();
                $this->changed = false;
            }
            switch ($this->mode) {
                case self::MODE_STREAM:
                    $plaintext = openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, $this->openssl_options);
                    break;
                case self::MODE_ECB:
                    if (!defined('OPENSSL_RAW_DATA')) {
                        $ciphertext.= @openssl_encrypt('', $this->cipher_name_openssl_ecb, $this->key, true);
                    }
                    $plaintext = openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, $this->openssl_options);
                    break;
                case self::MODE_CBC:
                    if (!defined('OPENSSL_RAW_DATA')) {
                        $padding = str_repeat(chr($this->block_size), $this->block_size) ^ substr($ciphertext, -$this->block_size);
                        $ciphertext.= substr(@openssl_encrypt($padding, $this->cipher_name_openssl_ecb, $this->key, true), 0, $this->block_size);
                        $offset = 2 * $this->block_size;
                    } else {
                        $offset = $this->block_size;
                    }
                    $plaintext = openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, $this->openssl_options, $this->decryptIV);
                    if ($this->continuousBuffer) {
                        $this->decryptIV = substr($ciphertext, -$offset, $this->block_size);
                    }
                    break;
                case self::MODE_CTR:
                    $plaintext = $this->_openssl_ctr_process($ciphertext, $this->decryptIV, $this->debuffer);
                    break;
                case self::MODE_CFB:
                    // cfb loosely routines inspired by openssl's:
                    // {@link http://cvs.openssl.org/fileview?f=openssl/crypto/modes/cfb128.c&v=1.3.2.2.2.1}
                    $plaintext = '';
                    if ($this->continuousBuffer) {
                        $iv = &$this->decryptIV;
                        $pos = &$this->debuffer['pos'];
                    } else {
                        $iv = $this->decryptIV;
                        $pos = 0;
                    }
                    $len = strlen($ciphertext);
                    $i = 0;
                    if ($pos) {
                        $orig_pos = $pos;
                        $max = $this->block_size - $pos;
                        if ($len >= $max) {
                            $i = $max;
                            $len-= $max;
                            $pos = 0;
                        } else {
                            $i = $len;
                            $pos+= $len;
                            $len = 0;
                        }
                        // ie. $i = min($max, $len), $len-= $i, $pos+= $i, $pos%= $this->blocksize
                        $plaintext = substr($iv, $orig_pos) ^ $ciphertext;
                        $iv = substr_replace($iv, substr($ciphertext, 0, $i), $orig_pos, $i);
                        $ciphertext = substr($ciphertext, $i);
                    }
                    $overflow = $len % $this->block_size;
                    if ($overflow) {
                        $plaintext.= openssl_decrypt(substr($ciphertext, 0, -$overflow), $this->cipher_name_openssl, $this->key, $this->openssl_options, $iv);
                        if ($len - $overflow) {
                            $iv = substr($ciphertext, -$overflow - $this->block_size, -$overflow);
                        }
                        $iv = openssl_encrypt(str_repeat("\0", $this->block_size), $this->cipher_name_openssl, $this->key, $this->openssl_options, $iv);
                        $plaintext.= $iv ^ substr($ciphertext, -$overflow);
                        $iv = substr_replace($iv, substr($ciphertext, -$overflow), 0, $overflow);
                        $pos = $overflow;
                    } elseif ($len) {
                        $plaintext.= openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, $this->openssl_options, $iv);
                        $iv = substr($ciphertext, -$this->block_size);
                    }
                    break;
                case self::MODE_CFB8:
                    $plaintext = openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, $this->openssl_options, $this->decryptIV);
                    if ($this->continuousBuffer) {
                        if (($len = strlen($ciphertext)) >= $this->block_size) {
                            $this->decryptIV = substr($ciphertext, -$this->block_size);
                        } else {
                            $this->decryptIV = substr($this->decryptIV, $len - $this->block_size) . substr($ciphertext, -$len);
                        }
                    }
                    break;
                case self::MODE_OFB8:
                    $plaintext = '';
                    $len = strlen($ciphertext);
                    $iv = $this->decryptIV;

                    for ($i = 0; $i < $len; ++$i) {
                        $xor = openssl_encrypt($iv, $this->cipher_name_openssl_ecb, $this->key, $this->openssl_options, $this->decryptIV);
                        $plaintext.= $ciphertext[$i] ^ $xor;
                        $iv = substr($iv, 1) . $xor[0];
                    }

                    if ($this->continuousBuffer) {
                        $this->decryptIV = $iv;
                    }
                    break;
                case self::MODE_OFB:
                    $plaintext = $this->_openssl_ofb_process($ciphertext, $this->decryptIV, $this->debuffer);
            }

            return $this->paddable ? $this->_unpad($plaintext) : $plaintext;
        }

        if ($this->engine === self::ENGINE_MCRYPT) {
            set_error_handler(array($this, 'do_nothing'));
            $block_size = $this->block_size;
            if ($this->changed) {
                $this->_setupMcrypt();
                $this->changed = false;
            }
            if ($this->dechanged) {
                mcrypt_generic_init($this->demcrypt, $this->key, $this->decryptIV);
                $this->dechanged = false;
            }

            if ($this->mode == self::MODE_CFB && $this->continuousBuffer) {
                $iv = &$this->decryptIV;
                $pos = &$this->debuffer['pos'];
                $len = strlen($ciphertext);
                $plaintext = '';
                $i = 0;
                if ($pos) {
                    $orig_pos = $pos;
                    $max = $block_size - $pos;
                    if ($len >= $max) {
                        $i = $max;
                        $len-= $max;
                        $pos = 0;
                    } else {
                        $i = $len;
                        $pos+= $len;
                        $len = 0;
                    }
                    // ie. $i = min($max, $len), $len-= $i, $pos+= $i, $pos%= $blocksize
                    $plaintext = substr($iv, $orig_pos) ^ $ciphertext;
                    $iv = substr_replace($iv, substr($ciphertext, 0, $i), $orig_pos, $i);
                }
                if ($len >= $block_size) {
                    $cb = substr($ciphertext, $i, $len - $len % $block_size);
                    $plaintext.= mcrypt_generic($this->ecb, $iv . $cb) ^ $cb;
                    $iv = substr($cb, -$block_size);
                    $len%= $block_size;
                }
                if ($len) {
                    $iv = mcrypt_generic($this->ecb, $iv);
                    $plaintext.= $iv ^ substr($ciphertext, -$len);
                    $iv = substr_replace($iv, substr($ciphertext, -$len), 0, $len);
                    $pos = $len;
                }

                restore_error_handler();

                return $plaintext;
            }

            $plaintext = mdecrypt_generic($this->demcrypt, $ciphertext);

            if (!$this->continuousBuffer) {
                mcrypt_generic_init($this->demcrypt, $this->key, $this->decryptIV);
            }

            restore_error_handler();

            return $this->paddable ? $this->_unpad($plaintext) : $plaintext;
        }

        if ($this->changed) {
            $this->_setup();
            $this->changed = false;
        }
        if ($this->use_inline_crypt) {
            $inline = $this->inline_crypt;
            return $inline('decrypt', $this, $ciphertext);
        }

        $block_size = $this->block_size;

        $buffer = &$this->debuffer;
        $plaintext = '';
        switch ($this->mode) {
            case self::MODE_ECB:
                for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                    $plaintext.= $this->_decryptBlock(substr($ciphertext, $i, $block_size));
                }
                break;
            case self::MODE_CBC:
                $xor = $this->decryptIV;
                for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                    $block = substr($ciphertext, $i, $block_size);
                    $plaintext.= $this->_decryptBlock($block) ^ $xor;
                    $xor = $block;
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                }
                break;
            case self::MODE_CTR:
                $xor = $this->decryptIV;
                if (strlen($buffer['ciphertext'])) {
                    for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                        $block = substr($ciphertext, $i, $block_size);
                        if (strlen($block) > strlen($buffer['ciphertext'])) {
                            $buffer['ciphertext'].= $this->_encryptBlock($xor);
                            $this->_increment_str($xor);
                        }
                        $key = $this->_string_shift($buffer['ciphertext'], $block_size);
                        $plaintext.= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                        $block = substr($ciphertext, $i, $block_size);
                        $key = $this->_encryptBlock($xor);
                        $this->_increment_str($xor);
                        $plaintext.= $block ^ $key;
                    }
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                    if ($start = strlen($ciphertext) % $block_size) {
                        $buffer['ciphertext'] = substr($key, $start) . $buffer['ciphertext'];
                    }
                }
                break;
            case self::MODE_CFB:
                if ($this->continuousBuffer) {
                    $iv = &$this->decryptIV;
                    $pos = &$buffer['pos'];
                } else {
                    $iv = $this->decryptIV;
                    $pos = 0;
                }
                $len = strlen($ciphertext);
                $i = 0;
                if ($pos) {
                    $orig_pos = $pos;
                    $max = $block_size - $pos;
                    if ($len >= $max) {
                        $i = $max;
                        $len-= $max;
                        $pos = 0;
                    } else {
                        $i = $len;
                        $pos+= $len;
                        $len = 0;
                    }
                    // ie. $i = min($max, $len), $len-= $i, $pos+= $i, $pos%= $blocksize
                    $plaintext = substr($iv, $orig_pos) ^ $ciphertext;
                    $iv = substr_replace($iv, substr($ciphertext, 0, $i), $orig_pos, $i);
                }
                while ($len >= $block_size) {
                    $iv = $this->_encryptBlock($iv);
                    $cb = substr($ciphertext, $i, $block_size);
                    $plaintext.= $iv ^ $cb;
                    $iv = $cb;
                    $len-= $block_size;
                    $i+= $block_size;
                }
                if ($len) {
                    $iv = $this->_encryptBlock($iv);
                    $plaintext.= $iv ^ substr($ciphertext, $i);
                    $iv = substr_replace($iv, substr($ciphertext, $i), 0, $len);
                    $pos = $len;
                }
                break;
            case self::MODE_CFB8:
                $plaintext = '';
                $len = strlen($ciphertext);
                $iv = $this->decryptIV;

                for ($i = 0; $i < $len; ++$i) {
                    $plaintext.= $ciphertext[$i] ^ $this->_encryptBlock($iv);
                    $iv = substr($iv, 1) . $ciphertext[$i];
                }

                if ($this->continuousBuffer) {
                    if ($len >= $block_size) {
                        $this->decryptIV = substr($ciphertext, -$block_size);
                    } else {
                        $this->decryptIV = substr($this->decryptIV, $len - $block_size) . substr($ciphertext, -$len);
                    }
                }
                break;
            case self::MODE_OFB8:
                $plaintext = '';
                $len = strlen($ciphertext);
                $iv = $this->decryptIV;

                for ($i = 0; $i < $len; ++$i) {
                    $xor = $this->_encryptBlock($iv);
                    $plaintext.= $ciphertext[$i] ^ $xor;
                    $iv = substr($iv, 1) . $xor[0];
                }

                if ($this->continuousBuffer) {
                    $this->decryptIV = $iv;
                }
                break;
            case self::MODE_OFB:
                $xor = $this->decryptIV;
                if (strlen($buffer['xor'])) {
                    for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                        $block = substr($ciphertext, $i, $block_size);
                        if (strlen($block) > strlen($buffer['xor'])) {
                            $xor = $this->_encryptBlock($xor);
                            $buffer['xor'].= $xor;
                        }
                        $key = $this->_string_shift($buffer['xor'], $block_size);
                        $plaintext.= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                        $xor = $this->_encryptBlock($xor);
                        $plaintext.= substr($ciphertext, $i, $block_size) ^ $xor;
                    }
                    $key = $xor;
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                    if ($start = strlen($ciphertext) % $block_size) {
                        $buffer['xor'] = substr($key, $start) . $buffer['xor'];
                    }
                }
                break;
            case self::MODE_STREAM:
                $plaintext = $this->_decryptBlock($ciphertext);
                break;
        }
        return $this->paddable ? $this->_unpad($plaintext) : $plaintext;
    }

    /**
     * OpenSSL CTR Processor
     *
     * PHP's OpenSSL bindings do not operate in continuous mode so we'll wrap around it. Since the keystream
     * for CTR is the same for both encrypting and decrypting this function is re-used by both Base::encrypt()
     * and Base::decrypt(). Also, OpenSSL doesn't implement CTR for all of it's symmetric ciphers so this
     * function will emulate CTR with ECB when necessary.
     *
     * @see self::encrypt()
     * @see self::decrypt()
     * @param string $plaintext
     * @param string $encryptIV
     * @param array $buffer
     * @return string
     * @access private
     */
    function _openssl_ctr_process($plaintext, &$encryptIV, &$buffer)
    {
        $ciphertext = '';

        $block_size = $this->block_size;
        $key = $this->key;

        if ($this->openssl_emulate_ctr) {
            $xor = $encryptIV;
            if (strlen($buffer['ciphertext'])) {
                for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                    $block = substr($plaintext, $i, $block_size);
                    if (strlen($block) > strlen($buffer['ciphertext'])) {
                        $result = @openssl_encrypt($xor, $this->cipher_name_openssl_ecb, $key, $this->openssl_options);
                        $result = !defined('OPENSSL_RAW_DATA') ? substr($result, 0, -$this->block_size) : $result;
                        $buffer['ciphertext'].= $result;
                    }
                    $this->_increment_str($xor);
                    $otp = $this->_string_shift($buffer['ciphertext'], $block_size);
                    $ciphertext.= $block ^ $otp;
                }
            } else {
                for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                    $block = substr($plaintext, $i, $block_size);
                    $otp = @openssl_encrypt($xor, $this->cipher_name_openssl_ecb, $key, $this->openssl_options);
                    $otp = !defined('OPENSSL_RAW_DATA') ? substr($otp, 0, -$this->block_size) : $otp;
                    $this->_increment_str($xor);
                    $ciphertext.= $block ^ $otp;
                }
            }
            if ($this->continuousBuffer) {
                $encryptIV = $xor;
                if ($start = strlen($plaintext) % $block_size) {
                    $buffer['ciphertext'] = substr($key, $start) . $buffer['ciphertext'];
                }
            }

            return $ciphertext;
        }

        if (strlen($buffer['ciphertext'])) {
            $ciphertext = $plaintext ^ $this->_string_shift($buffer['ciphertext'], strlen($plaintext));
            $plaintext = substr($plaintext, strlen($ciphertext));

            if (!strlen($plaintext)) {
                return $ciphertext;
            }
        }

        $overflow = strlen($plaintext) % $block_size;
        if ($overflow) {
            $plaintext2 = $this->_string_pop($plaintext, $overflow); // ie. trim $plaintext to a multiple of $block_size and put rest of $plaintext in $plaintext2
            $encrypted = openssl_encrypt($plaintext . str_repeat("\0", $block_size), $this->cipher_name_openssl, $key, $this->openssl_options, $encryptIV);
            $temp = $this->_string_pop($encrypted, $block_size);
            $ciphertext.= $encrypted . ($plaintext2 ^ $temp);
            if ($this->continuousBuffer) {
                $buffer['ciphertext'] = substr($temp, $overflow);
                $encryptIV = $temp;
            }
        } elseif (!strlen($buffer['ciphertext'])) {
            $ciphertext.= openssl_encrypt($plaintext . str_repeat("\0", $block_size), $this->cipher_name_openssl, $key, $this->openssl_options, $encryptIV);
            $temp = $this->_string_pop($ciphertext, $block_size);
            if ($this->continuousBuffer) {
                $encryptIV = $temp;
            }
        }
        if ($this->continuousBuffer) {
            if (!defined('OPENSSL_RAW_DATA')) {
                $encryptIV.= @openssl_encrypt('', $this->cipher_name_openssl_ecb, $key, $this->openssl_options);
            }
            $encryptIV = openssl_decrypt($encryptIV, $this->cipher_name_openssl_ecb, $key, $this->openssl_options);
            if ($overflow) {
                $this->_increment_str($encryptIV);
            }
        }

        return $ciphertext;
    }

    /**
     * OpenSSL OFB Processor
     *
     * PHP's OpenSSL bindings do not operate in continuous mode so we'll wrap around it. Since the keystream
     * for OFB is the same for both encrypting and decrypting this function is re-used by both Base::encrypt()
     * and Base::decrypt().
     *
     * @see self::encrypt()
     * @see self::decrypt()
     * @param string $plaintext
     * @param string $encryptIV
     * @param array $buffer
     * @return string
     * @access private
     */
    function _openssl_ofb_process($plaintext, &$encryptIV, &$buffer)
    {
        if (strlen($buffer['xor'])) {
            $ciphertext = $plaintext ^ $buffer['xor'];
            $buffer['xor'] = substr($buffer['xor'], strlen($ciphertext));
            $plaintext = substr($plaintext, strlen($ciphertext));
        } else {
            $ciphertext = '';
        }

        $block_size = $this->block_size;

        $len = strlen($plaintext);
        $key = $this->key;
        $overflow = $len % $block_size;

        if (strlen($plaintext)) {
            if ($overflow) {
                $ciphertext.= openssl_encrypt(substr($plaintext, 0, -$overflow) . str_repeat("\0", $block_size), $this->cipher_name_openssl, $key, $this->openssl_options, $encryptIV);
                $xor = $this->_string_pop($ciphertext, $block_size);
                if ($this->continuousBuffer) {
                    $encryptIV = $xor;
                }
                $ciphertext.= $this->_string_shift($xor, $overflow) ^ substr($plaintext, -$overflow);
                if ($this->continuousBuffer) {
                    $buffer['xor'] = $xor;
                }
            } else {
                $ciphertext = openssl_encrypt($plaintext, $this->cipher_name_openssl, $key, $this->openssl_options, $encryptIV);
                if ($this->continuousBuffer) {
                    $encryptIV = substr($ciphertext, -$block_size) ^ substr($plaintext, -$block_size);
                }
            }
        }

        return $ciphertext;
    }

    /**
     * phpseclib <-> OpenSSL Mode Mapper
     *
     * May need to be overwritten by classes extending this one in some cases
     *
     * @return int
     * @access private
     */
    function _openssl_translate_mode()
    {
        switch ($this->mode) {
            case self::MODE_ECB:
                return 'ecb';
            case self::MODE_CBC:
                return 'cbc';
            case self::MODE_CTR:
                return 'ctr';
            case self::MODE_CFB:
                return 'cfb';
            case self::MODE_CFB8:
                return 'cfb8';
            case self::MODE_OFB:
                return 'ofb';
        }
    }

    /**
     * Pad "packets".
     *
     * Block ciphers working by encrypting between their specified [$this->]block_size at a time
     * If you ever need to encrypt or decrypt something that isn't of the proper length, it becomes necessary to
     * pad the input so that it is of the proper length.
     *
     * Padding is enabled by default.  Sometimes, however, it is undesirable to pad strings.  Such is the case in SSH,
     * where "packets" are padded with random bytes before being encrypted.  Unpad these packets and you risk stripping
     * away characters that shouldn't be stripped away. (SSH knows how many bytes are added because the length is
     * transmitted separately)
     *
     * @see self::disablePadding()
     * @access public
     */
    function enablePadding()
    {
        $this->padding = true;
    }

    /**
     * Do not pad packets.
     *
     * @see self::enablePadding()
     * @access public
     */
    function disablePadding()
    {
        $this->padding = false;
    }

    /**
     * Treat consecutive "packets" as if they are a continuous buffer.
     *
     * Say you have a 32-byte plaintext $plaintext.  Using the default behavior, the two following code snippets
     * will yield different outputs:
     *
     * <code>
     *    echo $rijndael->encrypt(substr($plaintext,  0, 16));
     *    echo $rijndael->encrypt(substr($plaintext, 16, 16));
     * </code>
     * <code>
     *    echo $rijndael->encrypt($plaintext);
     * </code>
     *
     * The solution is to enable the continuous buffer.  Although this will resolve the above discrepancy, it creates
     * another, as demonstrated with the following:
     *
     * <code>
     *    $rijndael->encrypt(substr($plaintext, 0, 16));
     *    echo $rijndael->decrypt($rijndael->encrypt(substr($plaintext, 16, 16)));
     * </code>
     * <code>
     *    echo $rijndael->decrypt($rijndael->encrypt(substr($plaintext, 16, 16)));
     * </code>
     *
     * With the continuous buffer disabled, these would yield the same output.  With it enabled, they yield different
     * outputs.  The reason is due to the fact that the initialization vector's change after every encryption /
     * decryption round when the continuous buffer is enabled.  When it's disabled, they remain constant.
     *
     * Put another way, when the continuous buffer is enabled, the state of the \phpseclib\Crypt\*() object changes after each
     * encryption / decryption round, whereas otherwise, it'd remain constant.  For this reason, it's recommended that
     * continuous buffers not be used.  They do offer better security and are, in fact, sometimes required (SSH uses them),
     * however, they are also less intuitive and more likely to cause you problems.
     *
     * @see self::disableContinuousBuffer()
     * @access public
     * @internal Could, but not must, extend by the child Crypt_* class
     */
    function enableContinuousBuffer()
    {
        if ($this->mode == self::MODE_ECB) {
            return;
        }

        $this->continuousBuffer = true;

        $this->_setEngine();
    }

    /**
     * Treat consecutive packets as if they are a discontinuous buffer.
     *
     * The default behavior.
     *
     * @see self::enableContinuousBuffer()
     * @access public
     * @internal Could, but not must, extend by the child Crypt_* class
     */
    function disableContinuousBuffer()
    {
        if ($this->mode == self::MODE_ECB) {
            return;
        }
        if (!$this->continuousBuffer) {
            return;
        }

        $this->continuousBuffer = false;
        $this->changed = true;

        $this->_setEngine();
    }

    /**
     * Test for engine validity
     *
     * @see self::__construct()
     * @param int $engine
     * @access public
     * @return bool
     */
    function isValidEngine($engine)
    {
        switch ($engine) {
            case self::ENGINE_OPENSSL:
                if ($this->mode == self::MODE_STREAM && $this->continuousBuffer) {
                    return false;
                }
                $this->openssl_emulate_ctr = false;
                $result = $this->cipher_name_openssl &&
                          extension_loaded('openssl') &&
                          // PHP 5.3.0 - 5.3.2 did not let you set IV's
                          version_compare(PHP_VERSION, '5.3.3', '>=');
                if (!$result) {
                    return false;
                }

                // prior to PHP 5.4.0 OPENSSL_RAW_DATA and OPENSSL_ZERO_PADDING were not defined. instead of expecting an integer
                // $options openssl_encrypt expected a boolean $raw_data.
                if (!defined('OPENSSL_RAW_DATA')) {
                    $this->openssl_options = true;
                } else {
                    $this->openssl_options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;
                }

                $methods = openssl_get_cipher_methods();
                if (in_array($this->cipher_name_openssl, $methods)) {
                    return true;
                }
                // not all of openssl's symmetric cipher's support ctr. for those
                // that don't we'll emulate it
                switch ($this->mode) {
                    case self::MODE_CTR:
                        if (in_array($this->cipher_name_openssl_ecb, $methods)) {
                            $this->openssl_emulate_ctr = true;
                            return true;
                        }
                }
                return false;
            case self::ENGINE_MCRYPT:
                set_error_handler(array($this, 'do_nothing'));
                $result = $this->cipher_name_mcrypt &&
                       extension_loaded('mcrypt') &&
                       in_array($this->cipher_name_mcrypt, mcrypt_list_algorithms());
                restore_error_handler();
                return $result;
            case self::ENGINE_INTERNAL:
                return true;
        }

        return false;
    }

    /**
     * Sets the preferred crypt engine
     *
     * Currently, $engine could be:
     *
     * - \phpseclib\Crypt\Base::ENGINE_OPENSSL  [very fast]
     *
     * - \phpseclib\Crypt\Base::ENGINE_MCRYPT   [fast]
     *
     * - \phpseclib\Crypt\Base::ENGINE_INTERNAL [slow]
     *
     * If the preferred crypt engine is not available the fastest available one will be used
     *
     * @see self::__construct()
     * @param int $engine
     * @access public
     */
    function setPreferredEngine($engine)
    {
        switch ($engine) {
            //case self::ENGINE_OPENSSL;
            case self::ENGINE_MCRYPT:
            case self::ENGINE_INTERNAL:
                $this->preferredEngine = $engine;
                break;
            default:
                $this->preferredEngine = self::ENGINE_OPENSSL;
        }

        $this->_setEngine();
    }

    /**
     * Returns the engine currently being utilized
     *
     * @see self::_setEngine()
     * @access public
     */
    function getEngine()
    {
        return $this->engine;
    }

    /**
     * Sets the engine as appropriate
     *
     * @see self::__construct()
     * @access private
     */
    function _setEngine()
    {
        $this->engine = null;

        $candidateEngines = array(
            $this->preferredEngine,
            self::ENGINE_OPENSSL,
            self::ENGINE_MCRYPT
        );
        foreach ($candidateEngines as $engine) {
            if ($this->isValidEngine($engine)) {
                $this->engine = $engine;
                break;
            }
        }
        if (!$this->engine) {
            $this->engine = self::ENGINE_INTERNAL;
        }

        if ($this->engine != self::ENGINE_MCRYPT && $this->enmcrypt) {
            set_error_handler(array($this, 'do_nothing'));
            // Closing the current mcrypt resource(s). _mcryptSetup() will, if needed,
            // (re)open them with the module named in $this->cipher_name_mcrypt
            mcrypt_module_close($this->enmcrypt);
            mcrypt_module_close($this->demcrypt);
            $this->enmcrypt = null;
            $this->demcrypt = null;

            if ($this->ecb) {
                mcrypt_module_close($this->ecb);
                $this->ecb = null;
            }
            restore_error_handler();
        }

        $this->changed = true;
    }

    /**
     * Encrypts a block
     *
     * Note: Must be extended by the child \phpseclib\Crypt\* class
     *
     * @access private
     * @param string $in
     * @return string
     */
    abstract function _encryptBlock($in);

    /**
     * Decrypts a block
     *
     * Note: Must be extended by the child \phpseclib\Crypt\* class
     *
     * @access private
     * @param string $in
     * @return string
     */
    abstract function _decryptBlock($in);

    /**
     * Setup the key (expansion)
     *
     * Only used if $engine == self::ENGINE_INTERNAL
     *
     * Note: Must extend by the child \phpseclib\Crypt\* class
     *
     * @see self::_setup()
     * @access private
     */
    abstract function _setupKey();

    /**
     * Setup the self::ENGINE_INTERNAL $engine
     *
     * (re)init, if necessary, the internal cipher $engine and flush all $buffers
     * Used (only) if $engine == self::ENGINE_INTERNAL
     *
     * _setup() will be called each time if $changed === true
     * typically this happens when using one or more of following public methods:
     *
     * - setKey()
     *
     * - setIV()
     *
     * - disableContinuousBuffer()
     *
     * - First run of encrypt() / decrypt() with no init-settings
     *
     * @see self::setKey()
     * @see self::setIV()
     * @see self::disableContinuousBuffer()
     * @access private
     * @internal _setup() is always called before en/decryption.
     * @internal Could, but not must, extend by the child Crypt_* class
     */
    function _setup()
    {
        $this->_clearBuffers();
        $this->_setupKey();

        if ($this->use_inline_crypt) {
            $this->_setupInlineCrypt();
        }
    }

    /**
     * Setup the self::ENGINE_MCRYPT $engine
     *
     * (re)init, if necessary, the (ext)mcrypt resources and flush all $buffers
     * Used (only) if $engine = self::ENGINE_MCRYPT
     *
     * _setupMcrypt() will be called each time if $changed === true
     * typically this happens when using one or more of following public methods:
     *
     * - setKey()
     *
     * - setIV()
     *
     * - disableContinuousBuffer()
     *
     * - First run of encrypt() / decrypt()
     *
     * @see self::setKey()
     * @see self::setIV()
     * @see self::disableContinuousBuffer()
     * @access private
     * @internal Could, but not must, extend by the child Crypt_* class
     */
    function _setupMcrypt()
    {
        $this->_clearBuffers();
        $this->enchanged = $this->dechanged = true;

        if (!isset($this->enmcrypt)) {
            static $mcrypt_modes = array(
                self::MODE_CTR    => 'ctr',
                self::MODE_ECB    => MCRYPT_MODE_ECB,
                self::MODE_CBC    => MCRYPT_MODE_CBC,
                self::MODE_CFB    => 'ncfb',
                self::MODE_CFB8   => MCRYPT_MODE_CFB,
                self::MODE_OFB    => MCRYPT_MODE_NOFB,
                self::MODE_OFB8   => MCRYPT_MODE_OFB,
                self::MODE_STREAM => MCRYPT_MODE_STREAM,
            );

            $this->demcrypt = mcrypt_module_open($this->cipher_name_mcrypt, '', $mcrypt_modes[$this->mode], '');
            $this->enmcrypt = mcrypt_module_open($this->cipher_name_mcrypt, '', $mcrypt_modes[$this->mode], '');

            // we need the $ecb mcrypt resource (only) in MODE_CFB with enableContinuousBuffer()
            // to workaround mcrypt's broken ncfb implementation in buffered mode
            // see: {@link http://phpseclib.sourceforge.net/cfb-demo.phps}
            if ($this->mode == self::MODE_CFB) {
                $this->ecb = mcrypt_module_open($this->cipher_name_mcrypt, '', MCRYPT_MODE_ECB, '');
            }
        } // else should mcrypt_generic_deinit be called?

        if ($this->mode == self::MODE_CFB) {
            mcrypt_generic_init($this->ecb, $this->key, str_repeat("\0", $this->block_size));
        }
    }

    /**
     * Pads a string
     *
     * Pads a string using the RSA PKCS padding standards so that its length is a multiple of the blocksize.
     * $this->block_size - (strlen($text) % $this->block_size) bytes are added, each of which is equal to
     * chr($this->block_size - (strlen($text) % $this->block_size)
     *
     * If padding is disabled and $text is not a multiple of the blocksize, the string will be padded regardless
     * and padding will, hence forth, be enabled.
     *
     * @see self::_unpad()
     * @param string $text
     * @access private
     * @return string
     */
    function _pad($text)
    {
        $length = strlen($text);

        if (!$this->padding) {
            if ($length % $this->block_size == 0) {
                return $text;
            } else {
                user_error("The plaintext's length ($length) is not a multiple of the block size ({$this->block_size})");
                $this->padding = true;
            }
        }

        $pad = $this->block_size - ($length % $this->block_size);

        return str_pad($text, $length + $pad, chr($pad));
    }

    /**
     * Unpads a string.
     *
     * If padding is enabled and the reported padding length is invalid the encryption key will be assumed to be wrong
     * and false will be returned.
     *
     * @see self::_pad()
     * @param string $text
     * @access private
     * @return string
     */
    function _unpad($text)
    {
        if (!$this->padding) {
            return $text;
        }

        $length = ord($text[strlen($text) - 1]);

        if (!$length || $length > $this->block_size) {
            return false;
        }

        return substr($text, 0, -$length);
    }

    /**
     * Clears internal buffers
     *
     * Clearing/resetting the internal buffers is done everytime
     * after disableContinuousBuffer() or on cipher $engine (re)init
     * ie after setKey() or setIV()
     *
     * @access public
     * @internal Could, but not must, extend by the child Crypt_* class
     */
    function _clearBuffers()
    {
        $this->enbuffer = $this->debuffer = array('ciphertext' => '', 'xor' => '', 'pos' => 0, 'enmcrypt_init' => true);

        // mcrypt's handling of invalid's $iv:
        // $this->encryptIV = $this->decryptIV = strlen($this->iv) == $this->block_size ? $this->iv : str_repeat("\0", $this->block_size);
        $this->encryptIV = $this->decryptIV = str_pad(substr($this->iv, 0, $this->block_size), $this->block_size, "\0");

        if (!$this->skip_key_adjustment) {
            $this->key = str_pad(substr($this->key, 0, $this->key_length), $this->key_length, "\0");
        }
    }

    /**
     * String Shift
     *
     * Inspired by array_shift
     *
     * @param string $string
     * @param int $index
     * @access private
     * @return string
     */
    function _string_shift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }

    /**
     * String Pop
     *
     * Inspired by array_pop
     *
     * @param string $string
     * @param int $index
     * @access private
     * @return string
     */
    function _string_pop(&$string, $index = 1)
    {
        $substr = substr($string, -$index);
        $string = substr($string, 0, -$index);
        return $substr;
    }

    /**
     * Increment the current string
     *
     * @see self::decrypt()
     * @see self::encrypt()
     * @param string $var
     * @access private
     */
    function _increment_str(&$var)
    {
        if (function_exists('sodium_increment')) {
            $var = strrev($var);
            sodium_increment($var);
            $var = strrev($var);
            return;
        }

        for ($i = 4; $i <= strlen($var); $i+= 4) {
            $temp = substr($var, -$i, 4);
            switch ($temp) {
                case "\xFF\xFF\xFF\xFF":
                    $var = substr_replace($var, "\x00\x00\x00\x00", -$i, 4);
                    break;
                case "\x7F\xFF\xFF\xFF":
                    $var = substr_replace($var, "\x80\x00\x00\x00", -$i, 4);
                    return;
                default:
                    $temp = unpack('Nnum', $temp);
                    $var = substr_replace($var, pack('N', $temp['num'] + 1), -$i, 4);
                    return;
            }
        }

        $remainder = strlen($var) % 4;

        if ($remainder == 0) {
            return;
        }

        $temp = unpack('Nnum', str_pad(substr($var, 0, $remainder), 4, "\0", STR_PAD_LEFT));
        $temp = substr(pack('N', $temp['num'] + 1), -$remainder);
        $var = substr_replace($var, $temp, 0, $remainder);
    }

    /**
     * Setup the performance-optimized function for de/encrypt()
     *
     * Stores the created (or existing) callback function-name
     * in $this->inline_crypt
     *
     * Internally for phpseclib developers:
     *
     *     _setupInlineCrypt() would be called only if:
     *
     *     - $engine == self::ENGINE_INTERNAL and
     *
     *     - $use_inline_crypt === true
     *
     *     - each time on _setup(), after(!) _setupKey()
     *
     *
     *     This ensures that _setupInlineCrypt() has always a
     *     full ready2go initializated internal cipher $engine state
     *     where, for example, the keys allready expanded,
     *     keys/block_size calculated and such.
     *
     *     It is, each time if called, the responsibility of _setupInlineCrypt():
     *
     *     - to set $this->inline_crypt to a valid and fully working callback function
     *       as a (faster) replacement for encrypt() / decrypt()
     *
     *     - NOT to create unlimited callback functions (for memory reasons!)
     *       no matter how often _setupInlineCrypt() would be called. At some
     *       point of amount they must be generic re-useable.
     *
     *     - the code of _setupInlineCrypt() it self,
     *       and the generated callback code,
     *       must be, in following order:
     *       - 100% safe
     *       - 100% compatible to encrypt()/decrypt()
     *       - using only php5+ features/lang-constructs/php-extensions if
     *         compatibility (down to php4) or fallback is provided
     *       - readable/maintainable/understandable/commented and... not-cryptic-styled-code :-)
     *       - >= 10% faster than encrypt()/decrypt() [which is, by the way,
     *         the reason for the existence of _setupInlineCrypt() :-)]
     *       - memory-nice
     *       - short (as good as possible)
     *
     * Note: - _setupInlineCrypt() is using _createInlineCryptFunction() to create the full callback function code.
     *       - In case of using inline crypting, _setupInlineCrypt() must extend by the child \phpseclib\Crypt\* class.
     *       - The following variable names are reserved:
     *         - $_*  (all variable names prefixed with an underscore)
     *         - $self (object reference to it self. Do not use $this, but $self instead)
     *         - $in (the content of $in has to en/decrypt by the generated code)
     *       - The callback function should not use the 'return' statement, but en/decrypt'ing the content of $in only
     *
     *
     * @see self::_setup()
     * @see self::_createInlineCryptFunction()
     * @see self::encrypt()
     * @see self::decrypt()
     * @access private
     * @internal If a Crypt_* class providing inline crypting it must extend _setupInlineCrypt()
     */
    function _setupInlineCrypt()
    {
        // If, for any reason, an extending \phpseclib\Crypt\Base() \phpseclib\Crypt\* class
        // not using inline crypting then it must be ensured that: $this->use_inline_crypt = false
        // ie in the class var declaration of $use_inline_crypt in general for the \phpseclib\Crypt\* class,
        // in the constructor at object instance-time
        // or, if it's runtime-specific, at runtime

        $this->use_inline_crypt = false;
    }

    /**
     * Creates the performance-optimized function for en/decrypt()
     *
     * Internally for phpseclib developers:
     *
     *    _createInlineCryptFunction():
     *
     *    - merge the $cipher_code [setup'ed by _setupInlineCrypt()]
     *      with the current [$this->]mode of operation code
     *
     *    - create the $inline function, which called by encrypt() / decrypt()
     *      as its replacement to speed up the en/decryption operations.
     *
     *    - return the name of the created $inline callback function
     *
     *    - used to speed up en/decryption
     *
     *
     *
     *    The main reason why can speed up things [up to 50%] this way are:
     *
     *    - using variables more effective then regular.
     *      (ie no use of expensive arrays but integers $k_0, $k_1 ...
     *      or even, for example, the pure $key[] values hardcoded)
     *
     *    - avoiding 1000's of function calls of ie _encryptBlock()
     *      but inlining the crypt operations.
     *      in the mode of operation for() loop.
     *
     *    - full loop unroll the (sometimes key-dependent) rounds
     *      avoiding this way ++$i counters and runtime-if's etc...
     *
     *    The basic code architectur of the generated $inline en/decrypt()
     *    lambda function, in pseudo php, is:
     *
     *    <code>
     *    +----------------------------------------------------------------------------------------------+
     *    | callback $inline = create_function:                                                          |
     *    | lambda_function_0001_crypt_ECB($action, $text)                                               |
     *    | {                                                                                            |
     *    |     INSERT PHP CODE OF:                                                                      |
     *    |     $cipher_code['init_crypt'];                  // general init code.                       |
     *    |                                                  // ie: $sbox'es declarations used for       |
     *    |                                                  //     encrypt and decrypt'ing.             |
     *    |                                                                                              |
     *    |     switch ($action) {                                                                       |
     *    |         case 'encrypt':                                                                      |
     *    |             INSERT PHP CODE OF:                                                              |
     *    |             $cipher_code['init_encrypt'];       // encrypt sepcific init code.               |
     *    |                                                    ie: specified $key or $box                |
     *    |                                                        declarations for encrypt'ing.         |
     *    |                                                                                              |
     *    |             foreach ($ciphertext) {                                                          |
     *    |                 $in = $block_size of $ciphertext;                                            |
     *    |                                                                                              |
     *    |                 INSERT PHP CODE OF:                                                          |
     *    |                 $cipher_code['encrypt_block'];  // encrypt's (string) $in, which is always:  |
     *    |                                                 // strlen($in) == $this->block_size          |
     *    |                                                 // here comes the cipher algorithm in action |
     *    |                                                 // for encryption.                           |
     *    |                                                 // $cipher_code['encrypt_block'] has to      |
     *    |                                                 // encrypt the content of the $in variable   |
     *    |                                                                                              |
     *    |                 $plaintext .= $in;                                                           |
     *    |             }                                                                                |
     *    |             return $plaintext;                                                               |
     *    |                                                                                              |
     *    |         case 'decrypt':                                                                      |
     *    |             INSERT PHP CODE OF:                                                              |
     *    |             $cipher_code['init_decrypt'];       // decrypt sepcific init code                |
     *    |                                                    ie: specified $key or $box                |
     *    |                                                        declarations for decrypt'ing.         |
     *    |             foreach ($plaintext) {                                                           |
     *    |                 $in = $block_size of $plaintext;                                             |
     *    |                                                                                              |
     *    |                 INSERT PHP CODE OF:                                                          |
     *    |                 $cipher_code['decrypt_block'];  // decrypt's (string) $in, which is always   |
     *    |                                                 // strlen($in) == $this->block_size          |
     *    |                                                 // here comes the cipher algorithm in action |
     *    |                                                 // for decryption.                           |
     *    |                                                 // $cipher_code['decrypt_block'] has to      |
     *    |                                                 // decrypt the content of the $in variable   |
     *    |                 $ciphertext .= $in;                                                          |
     *    |             }                                                                                |
     *    |             return $ciphertext;                                                              |
     *    |     }                                                                                        |
     *    | }                                                                                            |
     *    +----------------------------------------------------------------------------------------------+
     *    </code>
     *
     *    See also the \phpseclib\Crypt\*::_setupInlineCrypt()'s for
     *    productive inline $cipher_code's how they works.
     *
     *    Structure of:
     *    <code>
     *    $cipher_code = array(
     *        'init_crypt'    => (string) '', // optional
     *        'init_encrypt'  => (string) '', // optional
     *        'init_decrypt'  => (string) '', // optional
     *        'encrypt_block' => (string) '', // required
     *        'decrypt_block' => (string) ''  // required
     *    );
     *    </code>
     *
     * @see self::_setupInlineCrypt()
     * @see self::encrypt()
     * @see self::decrypt()
     * @param array $cipher_code
     * @access private
     * @return string (the name of the created callback function)
     */
    function _createInlineCryptFunction($cipher_code)
    {
        $block_size = $this->block_size;

        // optional
        $init_crypt    = isset($cipher_code['init_crypt'])    ? $cipher_code['init_crypt']    : '';
        $init_encrypt  = isset($cipher_code['init_encrypt'])  ? $cipher_code['init_encrypt']  : '';
        $init_decrypt  = isset($cipher_code['init_decrypt'])  ? $cipher_code['init_decrypt']  : '';
        // required
        $encrypt_block = $cipher_code['encrypt_block'];
        $decrypt_block = $cipher_code['decrypt_block'];

        // Generating mode of operation inline code,
        // merged with the $cipher_code algorithm
        // for encrypt- and decryption.
        switch ($this->mode) {
            case self::MODE_ECB:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_plaintext_len = strlen($_text);

                    for ($_i = 0; $_i < $_plaintext_len; $_i+= '.$block_size.') {
                        $in = substr($_text, $_i, '.$block_size.');
                        '.$encrypt_block.'
                        $_ciphertext.= $in;
                    }

                    return $_ciphertext;
                    ';

                $decrypt = $init_decrypt . '
                    $_plaintext = "";
                    $_text = str_pad($_text, strlen($_text) + ('.$block_size.' - strlen($_text) % '.$block_size.') % '.$block_size.', chr(0));
                    $_ciphertext_len = strlen($_text);

                    for ($_i = 0; $_i < $_ciphertext_len; $_i+= '.$block_size.') {
                        $in = substr($_text, $_i, '.$block_size.');
                        '.$decrypt_block.'
                        $_plaintext.= $in;
                    }

                    return $self->_unpad($_plaintext);
                    ';
                break;
            case self::MODE_CTR:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_plaintext_len = strlen($_text);
                    $_xor = $self->encryptIV;
                    $_buffer = &$self->enbuffer;
                    if (strlen($_buffer["ciphertext"])) {
                        for ($_i = 0; $_i < $_plaintext_len; $_i+= '.$block_size.') {
                            $_block = substr($_text, $_i, '.$block_size.');
                            if (strlen($_block) > strlen($_buffer["ciphertext"])) {
                                $in = $_xor;
                                '.$encrypt_block.'
                                $self->_increment_str($_xor);
                                $_buffer["ciphertext"].= $in;
                            }
                            $_key = $self->_string_shift($_buffer["ciphertext"], '.$block_size.');
                            $_ciphertext.= $_block ^ $_key;
                        }
                    } else {
                        for ($_i = 0; $_i < $_plaintext_len; $_i+= '.$block_size.') {
                            $_block = substr($_text, $_i, '.$block_size.');
                            $in = $_xor;
                            '.$encrypt_block.'
                            $self->_increment_str($_xor);
                            $_key = $in;
                            $_ciphertext.= $_block ^ $_key;
                        }
                    }
                    if ($self->continuousBuffer) {
                        $self->encryptIV = $_xor;
                        if ($_start = $_plaintext_len % '.$block_size.') {
                            $_buffer["ciphertext"] = substr($_key, $_start) . $_buffer["ciphertext"];
                        }
                    }

                    return $_ciphertext;
                ';

                $decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_ciphertext_len = strlen($_text);
                    $_xor = $self->decryptIV;
                    $_buffer = &$self->debuffer;

                    if (strlen($_buffer["ciphertext"])) {
                        for ($_i = 0; $_i < $_ciphertext_len; $_i+= '.$block_size.') {
                            $_block = substr($_text, $_i, '.$block_size.');
                            if (strlen($_block) > strlen($_buffer["ciphertext"])) {
                                $in = $_xor;
                                '.$encrypt_block.'
                                $self->_increment_str($_xor);
                                $_buffer["ciphertext"].= $in;
                            }
                            $_key = $self->_string_shift($_buffer["ciphertext"], '.$block_size.');
                            $_plaintext.= $_block ^ $_key;
                        }
                    } else {
                        for ($_i = 0; $_i < $_ciphertext_len; $_i+= '.$block_size.') {
                            $_block = substr($_text, $_i, '.$block_size.');
                            $in = $_xor;
                            '.$encrypt_block.'
                            $self->_increment_str($_xor);
                            $_key = $in;
                            $_plaintext.= $_block ^ $_key;
                        }
                    }
                    if ($self->continuousBuffer) {
                        $self->decryptIV = $_xor;
                        if ($_start = $_ciphertext_len % '.$block_size.') {
                            $_buffer["ciphertext"] = substr($_key, $_start) . $_buffer["ciphertext"];
                        }
                    }

                    return $_plaintext;
                    ';
                break;
            case self::MODE_CFB:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_buffer = &$self->enbuffer;

                    if ($self->continuousBuffer) {
                        $_iv = &$self->encryptIV;
                        $_pos = &$_buffer["pos"];
                    } else {
                        $_iv = $self->encryptIV;
                        $_pos = 0;
                    }
                    $_len = strlen($_text);
                    $_i = 0;
                    if ($_pos) {
                        $_orig_pos = $_pos;
                        $_max = '.$block_size.' - $_pos;
                        if ($_len >= $_max) {
                            $_i = $_max;
                            $_len-= $_max;
                            $_pos = 0;
                        } else {
                            $_i = $_len;
                            $_pos+= $_len;
                            $_len = 0;
                        }
                        $_ciphertext = substr($_iv, $_orig_pos) ^ $_text;
                        $_iv = substr_replace($_iv, $_ciphertext, $_orig_pos, $_i);
                    }
                    while ($_len >= '.$block_size.') {
                        $in = $_iv;
                        '.$encrypt_block.';
                        $_iv = $in ^ substr($_text, $_i, '.$block_size.');
                        $_ciphertext.= $_iv;
                        $_len-= '.$block_size.';
                        $_i+= '.$block_size.';
                    }
                    if ($_len) {
                        $in = $_iv;
                        '.$encrypt_block.'
                        $_iv = $in;
                        $_block = $_iv ^ substr($_text, $_i);
                        $_iv = substr_replace($_iv, $_block, 0, $_len);
                        $_ciphertext.= $_block;
                        $_pos = $_len;
                    }
                    return $_ciphertext;
                ';

                $decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_buffer = &$self->debuffer;

                    if ($self->continuousBuffer) {
                        $_iv = &$self->decryptIV;
                        $_pos = &$_buffer["pos"];
                    } else {
                        $_iv = $self->decryptIV;
                        $_pos = 0;
                    }
                    $_len = strlen($_text);
                    $_i = 0;
                    if ($_pos) {
                        $_orig_pos = $_pos;
                        $_max = '.$block_size.' - $_pos;
                        if ($_len >= $_max) {
                            $_i = $_max;
                            $_len-= $_max;
                            $_pos = 0;
                        } else {
                            $_i = $_len;
                            $_pos+= $_len;
                            $_len = 0;
                        }
                        $_plaintext = substr($_iv, $_orig_pos) ^ $_text;
                        $_iv = substr_replace($_iv, substr($_text, 0, $_i), $_orig_pos, $_i);
                    }
                    while ($_len >= '.$block_size.') {
                        $in = $_iv;
                        '.$encrypt_block.'
                        $_iv = $in;
                        $cb = substr($_text, $_i, '.$block_size.');
                        $_plaintext.= $_iv ^ $cb;
                        $_iv = $cb;
                        $_len-= '.$block_size.';
                        $_i+= '.$block_size.';
                    }
                    if ($_len) {
                        $in = $_iv;
                        '.$encrypt_block.'
                        $_iv = $in;
                        $_plaintext.= $_iv ^ substr($_text, $_i);
                        $_iv = substr_replace($_iv, substr($_text, $_i), 0, $_len);
                        $_pos = $_len;
                    }

                    return $_plaintext;
                    ';
                break;
            case self::MODE_CFB8:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_len = strlen($_text);
                    $_iv = $self->encryptIV;

                    for ($_i = 0; $_i < $_len; ++$_i) {
                        $in = $_iv;
                        '.$encrypt_block.'
                        $_ciphertext.= ($_c = $_text[$_i] ^ $in);
                        $_iv = substr($_iv, 1) . $_c;
                    }

                    if ($self->continuousBuffer) {
                        if ($_len >= '.$block_size.') {
                            $self->encryptIV = substr($_ciphertext, -'.$block_size.');
                        } else {
                            $self->encryptIV = substr($self->encryptIV, $_len - '.$block_size.') . substr($_ciphertext, -$_len);
                        }
                    }

                    return $_ciphertext;
                    ';
                $decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_len = strlen($_text);
                    $_iv = $self->decryptIV;

                    for ($_i = 0; $_i < $_len; ++$_i) {
                        $in = $_iv;
                        '.$encrypt_block.'
                        $_plaintext.= $_text[$_i] ^ $in;
                        $_iv = substr($_iv, 1) . $_text[$_i];
                    }

                    if ($self->continuousBuffer) {
                        if ($_len >= '.$block_size.') {
                            $self->decryptIV = substr($_text, -'.$block_size.');
                        } else {
                            $self->decryptIV = substr($self->decryptIV, $_len - '.$block_size.') . substr($_text, -$_len);
                        }
                    }

                    return $_plaintext;
                    ';
                break;
            case self::MODE_OFB8:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_len = strlen($_text);
                    $_iv = $self->encryptIV;

                    for ($_i = 0; $_i < $_len; ++$_i) {
                        $in = $_iv;
                        '.$encrypt_block.'
                        $_ciphertext.= $_text[$_i] ^ $in;
                        $_iv = substr($_iv, 1) . $in[0];
                    }

                    if ($self->continuousBuffer) {
                        $self->encryptIV = $_iv;
                    }

                    return $_ciphertext;
                    ';
                $decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_len = strlen($_text);
                    $_iv = $self->decryptIV;

                    for ($_i = 0; $_i < $_len; ++$_i) {
                        $in = $_iv;
                        '.$encrypt_block.'
                        $_plaintext.= $_text[$_i] ^ $in;
                        $_iv = substr($_iv, 1) . $in[0];
                    }

                    if ($self->continuousBuffer) {
                        $self->decryptIV = $_iv;
                    }

                    return $_plaintext;
                    ';
                break;
            case self::MODE_OFB:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_plaintext_len = strlen($_text);
                    $_xor = $self->encryptIV;
                    $_buffer = &$self->enbuffer;

                    if (strlen($_buffer["xor"])) {
                        for ($_i = 0; $_i < $_plaintext_len; $_i+= '.$block_size.') {
                            $_block = substr($_text, $_i, '.$block_size.');
                            if (strlen($_block) > strlen($_buffer["xor"])) {
                                $in = $_xor;
                                '.$encrypt_block.'
                                $_xor = $in;
                                $_buffer["xor"].= $_xor;
                            }
                            $_key = $self->_string_shift($_buffer["xor"], '.$block_size.');
                            $_ciphertext.= $_block ^ $_key;
                        }
                    } else {
                        for ($_i = 0; $_i < $_plaintext_len; $_i+= '.$block_size.') {
                            $in = $_xor;
                            '.$encrypt_block.'
                            $_xor = $in;
                            $_ciphertext.= substr($_text, $_i, '.$block_size.') ^ $_xor;
                        }
                        $_key = $_xor;
                    }
                    if ($self->continuousBuffer) {
                        $self->encryptIV = $_xor;
                        if ($_start = $_plaintext_len % '.$block_size.') {
                             $_buffer["xor"] = substr($_key, $_start) . $_buffer["xor"];
                        }
                    }
                    return $_ciphertext;
                    ';

                $decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_ciphertext_len = strlen($_text);
                    $_xor = $self->decryptIV;
                    $_buffer = &$self->debuffer;

                    if (strlen($_buffer["xor"])) {
                        for ($_i = 0; $_i < $_ciphertext_len; $_i+= '.$block_size.') {
                            $_block = substr($_text, $_i, '.$block_size.');
                            if (strlen($_block) > strlen($_buffer["xor"])) {
                                $in = $_xor;
                                '.$encrypt_block.'
                                $_xor = $in;
                                $_buffer["xor"].= $_xor;
                            }
                            $_key = $self->_string_shift($_buffer["xor"], '.$block_size.');
                            $_plaintext.= $_block ^ $_key;
                        }
                    } else {
                        for ($_i = 0; $_i < $_ciphertext_len; $_i+= '.$block_size.') {
                            $in = $_xor;
                            '.$encrypt_block.'
                            $_xor = $in;
                            $_plaintext.= substr($_text, $_i, '.$block_size.') ^ $_xor;
                        }
                        $_key = $_xor;
                    }
                    if ($self->continuousBuffer) {
                        $self->decryptIV = $_xor;
                        if ($_start = $_ciphertext_len % '.$block_size.') {
                             $_buffer["xor"] = substr($_key, $_start) . $_buffer["xor"];
                        }
                    }
                    return $_plaintext;
                    ';
                break;
            case self::MODE_STREAM:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    '.$encrypt_block.'
                    return $_ciphertext;
                    ';
                $decrypt = $init_decrypt . '
                    $_plaintext = "";
                    '.$decrypt_block.'
                    return $_plaintext;
                    ';
                break;
            // case self::MODE_CBC:
            default:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_plaintext_len = strlen($_text);

                    $in = $self->encryptIV;

                    for ($_i = 0; $_i < $_plaintext_len; $_i+= '.$block_size.') {
                        $in = substr($_text, $_i, '.$block_size.') ^ $in;
                        '.$encrypt_block.'
                        $_ciphertext.= $in;
                    }

                    if ($self->continuousBuffer) {
                        $self->encryptIV = $in;
                    }

                    return $_ciphertext;
                    ';

                $decrypt = $init_decrypt . '
                    $_plaintext = "";
                    $_text = str_pad($_text, strlen($_text) + ('.$block_size.' - strlen($_text) % '.$block_size.') % '.$block_size.', chr(0));
                    $_ciphertext_len = strlen($_text);

                    $_iv = $self->decryptIV;

                    for ($_i = 0; $_i < $_ciphertext_len; $_i+= '.$block_size.') {
                        $in = $_block = substr($_text, $_i, '.$block_size.');
                        '.$decrypt_block.'
                        $_plaintext.= $in ^ $_iv;
                        $_iv = $_block;
                    }

                    if ($self->continuousBuffer) {
                        $self->decryptIV = $_iv;
                    }

                    return $self->_unpad($_plaintext);
                    ';
                break;
        }

        // Create the $inline function and return its name as string. Ready to run!
        eval('$func = function ($_action, &$self, $_text) { ' . $init_crypt . 'if ($_action == "encrypt") { ' . $encrypt . ' } else { ' . $decrypt . ' } };');
        return $func;
    }

    /**
     * Holds the lambda_functions table (classwide)
     *
     * Each name of the lambda function, created from
     * _setupInlineCrypt() && _createInlineCryptFunction()
     * is stored, classwide (!), here for reusing.
     *
     * The string-based index of $function is a classwide
     * unique value representing, at least, the $mode of
     * operation (or more... depends of the optimizing level)
     * for which $mode the lambda function was created.
     *
     * @access private
     * @return array &$functions
     */
    function &_getLambdaFunctions()
    {
        static $functions = array();
        return $functions;
    }

    /**
     * Generates a digest from $bytes
     *
     * @see self::_setupInlineCrypt()
     * @access private
     * @param string $bytes
     * @return string
     */
    function _hashInlineCryptFunction($bytes)
    {
        if (!isset(self::$WHIRLPOOL_AVAILABLE)) {
            self::$WHIRLPOOL_AVAILABLE = extension_loaded('hash') && in_array('whirlpool', hash_algos());
        }

        $result = '';
        $hash = $bytes;

        switch (true) {
            case self::$WHIRLPOOL_AVAILABLE:
                foreach (str_split($bytes, 64) as $t) {
                    $hash = hash('whirlpool', $hash, true);
                    $result .= $t ^ $hash;
                }
                return $result . hash('whirlpool', $hash, true);
            default:
                $len = strlen($bytes);
                for ($i = 0; $i < $len; $i+=20) {
                    $t = substr($bytes, $i, 20);
                    $hash = pack('H*', sha1($hash));
                    $result .= $t ^ $hash;
                }
                return $result . pack('H*', sha1($hash));
        }
    }

    /**
     * Convert float to int
     *
     * On ARM CPUs converting floats to ints doesn't always work
     *
     * @access private
     * @param string $x
     * @return int
     */
    function safe_intval($x)
    {
        if (is_int($x)) {
            return $x;
        }
        return (fmod($x, 0x80000000) & 0x7FFFFFFF) |
            ((fmod(floor($x / 0x80000000), 2) & 1) << 31);
    }

    /**
     * eval()'able string for in-line float to int
     *
     * @access private
     * @return string
     */
    function safe_intval_inline()
    {
        if (CRYPT_BASE_USE_REG_INTVAL) {
            return PHP_INT_SIZE == 4 ? 'intval(%s)' : '%s';
        }

        $safeint = '(is_int($temp = %s) ? $temp : (fmod($temp, 0x80000000) & 0x7FFFFFFF) | ';
        return $safeint . '((fmod(floor($temp / 0x80000000), 2) & 1) << 31))';
    }

    /**
     * Dummy error handler to suppress mcrypt errors
     *
     * @access private
     */
    function do_nothing()
    {
    }
}


/**
 * Pure-PHP implementation of Rijndael.
 *
 * Uses mcrypt, if available/possible, and an internal implementation, otherwise.
 *
 * PHP version 5
 *
 * If {@link self::setBlockLength() setBlockLength()} isn't called, it'll be assumed to be 128 bits.  If
 * {@link self::setKeyLength() setKeyLength()} isn't called, it'll be calculated from
 * {@link self::setKey() setKey()}.  ie. if the key is 128-bits, the key length will be 128-bits.  If it's
 * 136-bits it'll be null-padded to 192-bits and 192 bits will be the key length until
 * {@link self::setKey() setKey()} is called, again, at which point, it'll be recalculated.
 *
 * Not all Rijndael implementations may support 160-bits or 224-bits as the block length / key length.  mcrypt, for example,
 * does not.  AES, itself, only supports block lengths of 128 and key lengths of 128, 192, and 256.
 * {@link http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf#page=10 Rijndael-ammended.pdf#page=10} defines the
 * algorithm for block lengths of 192 and 256 but not for block lengths / key lengths of 160 and 224.  Indeed, 160 and 224
 * are first defined as valid key / block lengths in
 * {@link http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf#page=44 Rijndael-ammended.pdf#page=44}:
 * Extensions: Other block and Cipher Key lengths.
 * Note: Use of 160/224-bit Keys must be explicitly set by setKeyLength(160) respectively setKeyLength(224).
 *
 * {@internal The variable names are the same as those in
 * {@link http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf#page=10 fips-197.pdf#page=10}.}}
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $rijndael = new \phpseclib\Crypt\Rijndael();
 *
 *    $rijndael->setKey('abcdefghijklmnop');
 *
 *    $size = 10 * 1024;
 *    $plaintext = '';
 *    for ($i = 0; $i < $size; $i++) {
 *        $plaintext.= 'a';
 *    }
 *
 *    echo $rijndael->decrypt($rijndael->encrypt($plaintext));
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   Rijndael
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2008 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

/**
 * Pure-PHP implementation of Rijndael.
 *
 * @package Rijndael
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class KiboboCryptRijndael extends KiboboCryptBase
{
    /**
     * The mcrypt specific name of the cipher
     *
     * Mcrypt is useable for 128/192/256-bit $block_size/$key_length. For 160/224 not.
     * \phpseclib\Crypt\Rijndael determines automatically whether mcrypt is useable
     * or not for the current $block_size/$key_length.
     * In case of, $cipher_name_mcrypt will be set dynamically at run time accordingly.
     *
     * @see \phpseclib\Crypt\Base::cipher_name_mcrypt
     * @see \phpseclib\Crypt\Base::engine
     * @see self::isValidEngine()
     * @var string
     * @access private
     */
    var $cipher_name_mcrypt = 'rijndael-128';

    /**
     * The default salt used by setPassword()
     *
     * @see \phpseclib\Crypt\Base::password_default_salt
     * @see \phpseclib\Crypt\Base::setPassword()
     * @var string
     * @access private
     */
    var $password_default_salt = 'phpseclib';

    /**
     * The Key Schedule
     *
     * @see self::_setup()
     * @var array
     * @access private
     */
    var $w;

    /**
     * The Inverse Key Schedule
     *
     * @see self::_setup()
     * @var array
     * @access private
     */
    var $dw;

    /**
     * The Block Length divided by 32
     *
     * @see self::setBlockLength()
     * @var int
     * @access private
     * @internal The max value is 256 / 32 = 8, the min value is 128 / 32 = 4.  Exists in conjunction with $block_size
     *    because the encryption / decryption / key schedule creation requires this number and not $block_size.  We could
     *    derive this from $block_size or vice versa, but that'd mean we'd have to do multiple shift operations, so in lieu
     *    of that, we'll just precompute it once.
     */
    var $Nb = 4;

    /**
     * The Key Length (in bytes)
     *
     * @see self::setKeyLength()
     * @var int
     * @access private
     * @internal The max value is 256 / 8 = 32, the min value is 128 / 8 = 16.  Exists in conjunction with $Nk
     *    because the encryption / decryption / key schedule creation requires this number and not $key_length.  We could
     *    derive this from $key_length or vice versa, but that'd mean we'd have to do multiple shift operations, so in lieu
     *    of that, we'll just precompute it once.
     */
    var $key_length = 16;

    /**
     * The Key Length divided by 32
     *
     * @see self::setKeyLength()
     * @var int
     * @access private
     * @internal The max value is 256 / 32 = 8, the min value is 128 / 32 = 4
     */
    var $Nk = 4;

    /**
     * The Number of Rounds
     *
     * @var int
     * @access private
     * @internal The max value is 14, the min value is 10.
     */
    var $Nr;

    /**
     * Shift offsets
     *
     * @var array
     * @access private
     */
    var $c;

    /**
     * Holds the last used key- and block_size information
     *
     * @var array
     * @access private
     */
    var $kl;

    /**
     * Sets the key length.
     *
     * Valid key lengths are 128, 160, 192, 224, and 256.  If the length is less than 128, it will be rounded up to
     * 128.  If the length is greater than 128 and invalid, it will be rounded down to the closest valid amount.
     *
     * Note: phpseclib extends Rijndael (and AES) for using 160- and 224-bit keys but they are officially not defined
     *       and the most (if not all) implementations are not able using 160/224-bit keys but round/pad them up to
     *       192/256 bits as, for example, mcrypt will do.
     *
     *       That said, if you want be compatible with other Rijndael and AES implementations,
     *       you should not setKeyLength(160) or setKeyLength(224).
     *
     * Additional: In case of 160- and 224-bit keys, phpseclib will/can, for that reason, not use
     *             the mcrypt php extension, even if available.
     *             This results then in slower encryption.
     *
     * @access public
     * @param int $length
     */
    function setKeyLength($length)
    {
        switch (true) {
            case $length <= 128:
                $this->key_length = 16;
                break;
            case $length <= 160:
                $this->key_length = 20;
                break;
            case $length <= 192:
                $this->key_length = 24;
                break;
            case $length <= 224:
                $this->key_length = 28;
                break;
            default:
                $this->key_length = 32;
        }

        parent::setKeyLength($length);
    }

    /**
     * Sets the block length
     *
     * Valid block lengths are 128, 160, 192, 224, and 256.  If the length is less than 128, it will be rounded up to
     * 128.  If the length is greater than 128 and invalid, it will be rounded down to the closest valid amount.
     *
     * @access public
     * @param int $length
     */
    function setBlockLength($length)
    {
        $length >>= 5;
        if ($length > 8) {
            $length = 8;
        } elseif ($length < 4) {
            $length = 4;
        }
        $this->Nb = $length;
        $this->block_size = $length << 2;
        $this->changed = true;
        $this->_setEngine();
    }

    /**
     * Test for engine validity
     *
     * This is mainly just a wrapper to set things up for \phpseclib\Crypt\Base::isValidEngine()
     *
     * @see \phpseclib\Crypt\Base::__construct()
     * @param int $engine
     * @access public
     * @return bool
     */
    function isValidEngine($engine)
    {
        switch ($engine) {
            case self::ENGINE_OPENSSL:
                if ($this->block_size != 16) {
                    return false;
                }
                $this->cipher_name_openssl_ecb = 'aes-' . ($this->key_length << 3) . '-ecb';
                $this->cipher_name_openssl = 'aes-' . ($this->key_length << 3) . '-' . $this->_openssl_translate_mode();
                break;
            case self::ENGINE_MCRYPT:
                $this->cipher_name_mcrypt = 'rijndael-' . ($this->block_size << 3);
                if ($this->key_length % 8) { // is it a 160/224-bit key?
                    // mcrypt is not usable for them, only for 128/192/256-bit keys
                    return false;
                }
        }

        return parent::isValidEngine($engine);
    }

    /**
     * Encrypts a block
     *
     * @access private
     * @param string $in
     * @return string
     */
    function _encryptBlock($in)
    {
        static $tables;
        if (empty($tables)) {
            $tables = &$this->_getTables();
        }
        $t0   = $tables[0];
        $t1   = $tables[1];
        $t2   = $tables[2];
        $t3   = $tables[3];
        $sbox = $tables[4];

        $state = array();
        $words = unpack('N*', $in);

        $c = $this->c;
        $w = $this->w;
        $Nb = $this->Nb;
        $Nr = $this->Nr;

        // addRoundKey
        $wc = $Nb - 1;
        foreach ($words as $word) {
            $state[] = $word ^ $w[++$wc];
        }

        // fips-197.pdf#page=19, "Figure 5. Pseudo Code for the Cipher", states that this loop has four components -
        // subBytes, shiftRows, mixColumns, and addRoundKey. fips-197.pdf#page=30, "Implementation Suggestions Regarding
        // Various Platforms" suggests that performs enhanced implementations are described in Rijndael-ammended.pdf.
        // Rijndael-ammended.pdf#page=20, "Implementation aspects / 32-bit processor", discusses such an optimization.
        // Unfortunately, the description given there is not quite correct.  Per aes.spec.v316.pdf#page=19 [1],
        // equation (7.4.7) is supposed to use addition instead of subtraction, so we'll do that here, as well.

        // [1] http://fp.gladman.plus.com/cryptography_technology/rijndael/aes.spec.v316.pdf
        $temp = array();
        for ($round = 1; $round < $Nr; ++$round) {
            $i = 0; // $c[0] == 0
            $j = $c[1];
            $k = $c[2];
            $l = $c[3];

            while ($i < $Nb) {
                $temp[$i] = $t0[$state[$i] >> 24 & 0x000000FF] ^
                            $t1[$state[$j] >> 16 & 0x000000FF] ^
                            $t2[$state[$k] >>  8 & 0x000000FF] ^
                            $t3[$state[$l]       & 0x000000FF] ^
                            $w[++$wc];
                ++$i;
                $j = ($j + 1) % $Nb;
                $k = ($k + 1) % $Nb;
                $l = ($l + 1) % $Nb;
            }
            $state = $temp;
        }

        // subWord
        for ($i = 0; $i < $Nb; ++$i) {
            $state[$i] =   $sbox[$state[$i]       & 0x000000FF]        |
                          ($sbox[$state[$i] >>  8 & 0x000000FF] <<  8) |
                          ($sbox[$state[$i] >> 16 & 0x000000FF] << 16) |
                          ($sbox[$state[$i] >> 24 & 0x000000FF] << 24);
        }

        // shiftRows + addRoundKey
        $i = 0; // $c[0] == 0
        $j = $c[1];
        $k = $c[2];
        $l = $c[3];
        while ($i < $Nb) {
            $temp[$i] = ($state[$i] & intval(0xFF000000)) ^
                        ($state[$j] & 0x00FF0000) ^
                        ($state[$k] & 0x0000FF00) ^
                        ($state[$l] & 0x000000FF) ^
                         $w[$i];
            ++$i;
            $j = ($j + 1) % $Nb;
            $k = ($k + 1) % $Nb;
            $l = ($l + 1) % $Nb;
        }

        switch ($Nb) {
            case 8:
                return pack('N*', $temp[0], $temp[1], $temp[2], $temp[3], $temp[4], $temp[5], $temp[6], $temp[7]);
            case 7:
                return pack('N*', $temp[0], $temp[1], $temp[2], $temp[3], $temp[4], $temp[5], $temp[6]);
            case 6:
                return pack('N*', $temp[0], $temp[1], $temp[2], $temp[3], $temp[4], $temp[5]);
            case 5:
                return pack('N*', $temp[0], $temp[1], $temp[2], $temp[3], $temp[4]);
            default:
                return pack('N*', $temp[0], $temp[1], $temp[2], $temp[3]);
        }
    }

    /**
     * Decrypts a block
     *
     * @access private
     * @param string $in
     * @return string
     */
    function _decryptBlock($in)
    {
        static $invtables;
        if (empty($invtables)) {
            $invtables = &$this->_getInvTables();
        }
        $dt0   = $invtables[0];
        $dt1   = $invtables[1];
        $dt2   = $invtables[2];
        $dt3   = $invtables[3];
        $isbox = $invtables[4];

        $state = array();
        $words = unpack('N*', $in);

        $c  = $this->c;
        $dw = $this->dw;
        $Nb = $this->Nb;
        $Nr = $this->Nr;

        // addRoundKey
        $wc = $Nb - 1;
        foreach ($words as $word) {
            $state[] = $word ^ $dw[++$wc];
        }

        $temp = array();
        for ($round = $Nr - 1; $round > 0; --$round) {
            $i = 0; // $c[0] == 0
            $j = $Nb - $c[1];
            $k = $Nb - $c[2];
            $l = $Nb - $c[3];

            while ($i < $Nb) {
                $temp[$i] = $dt0[$state[$i] >> 24 & 0x000000FF] ^
                            $dt1[$state[$j] >> 16 & 0x000000FF] ^
                            $dt2[$state[$k] >>  8 & 0x000000FF] ^
                            $dt3[$state[$l]       & 0x000000FF] ^
                            $dw[++$wc];
                ++$i;
                $j = ($j + 1) % $Nb;
                $k = ($k + 1) % $Nb;
                $l = ($l + 1) % $Nb;
            }
            $state = $temp;
        }

        // invShiftRows + invSubWord + addRoundKey
        $i = 0; // $c[0] == 0
        $j = $Nb - $c[1];
        $k = $Nb - $c[2];
        $l = $Nb - $c[3];

        while ($i < $Nb) {
            $word = ($state[$i] & intval(0xFF000000)) |
                    ($state[$j] & 0x00FF0000) |
                    ($state[$k] & 0x0000FF00) |
                    ($state[$l] & 0x000000FF);

            $temp[$i] = $dw[$i] ^ ($isbox[$word       & 0x000000FF]        |
                                  ($isbox[$word >>  8 & 0x000000FF] <<  8) |
                                  ($isbox[$word >> 16 & 0x000000FF] << 16) |
                                  ($isbox[$word >> 24 & 0x000000FF] << 24));
            ++$i;
            $j = ($j + 1) % $Nb;
            $k = ($k + 1) % $Nb;
            $l = ($l + 1) % $Nb;
        }

        switch ($Nb) {
            case 8:
                return pack('N*', $temp[0], $temp[1], $temp[2], $temp[3], $temp[4], $temp[5], $temp[6], $temp[7]);
            case 7:
                return pack('N*', $temp[0], $temp[1], $temp[2], $temp[3], $temp[4], $temp[5], $temp[6]);
            case 6:
                return pack('N*', $temp[0], $temp[1], $temp[2], $temp[3], $temp[4], $temp[5]);
            case 5:
                return pack('N*', $temp[0], $temp[1], $temp[2], $temp[3], $temp[4]);
            default:
                return pack('N*', $temp[0], $temp[1], $temp[2], $temp[3]);
        }
    }

    /**
     * Setup the key (expansion)
     *
     * @see \phpseclib\Crypt\Base::_setupKey()
     * @access private
     */
    function _setupKey()
    {
        // Each number in $rcon is equal to the previous number multiplied by two in Rijndael's finite field.
        // See http://en.wikipedia.org/wiki/Finite_field_arithmetic#Multiplicative_inverse
        static $rcon;

        if (!isset($rcon)) {
            $rcon = array(0,
                0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000,
                0x6C000000, 0xD8000000, 0xAB000000, 0x4D000000, 0x9A000000,
                0x2F000000, 0x5E000000, 0xBC000000, 0x63000000, 0xC6000000,
                0x97000000, 0x35000000, 0x6A000000, 0xD4000000, 0xB3000000,
                0x7D000000, 0xFA000000, 0xEF000000, 0xC5000000, 0x91000000
            );
            $rcon = array_map('intval', $rcon);
        }

        if (isset($this->kl['key']) && $this->key === $this->kl['key'] && $this->key_length === $this->kl['key_length'] && $this->block_size === $this->kl['block_size']) {
            // already expanded
            return;
        }
        $this->kl = array('key' => $this->key, 'key_length' => $this->key_length, 'block_size' => $this->block_size);

        $this->Nk = $this->key_length >> 2;
        // see Rijndael-ammended.pdf#page=44
        $this->Nr = max($this->Nk, $this->Nb) + 6;

        // shift offsets for Nb = 5, 7 are defined in Rijndael-ammended.pdf#page=44,
        //     "Table 8: Shift offsets in Shiftrow for the alternative block lengths"
        // shift offsets for Nb = 4, 6, 8 are defined in Rijndael-ammended.pdf#page=14,
        //     "Table 2: Shift offsets for different block lengths"
        switch ($this->Nb) {
            case 4:
            case 5:
            case 6:
                $this->c = array(0, 1, 2, 3);
                break;
            case 7:
                $this->c = array(0, 1, 2, 4);
                break;
            case 8:
                $this->c = array(0, 1, 3, 4);
        }

        $w = array_values(unpack('N*words', $this->key));

        $length = $this->Nb * ($this->Nr + 1);
        for ($i = $this->Nk; $i < $length; $i++) {
            $temp = $w[$i - 1];
            if ($i % $this->Nk == 0) {
                // according to <http://php.net/language.types.integer>, "the size of an integer is platform-dependent".
                // on a 32-bit machine, it's 32-bits, and on a 64-bit machine, it's 64-bits. on a 32-bit machine,
                // 0xFFFFFFFF << 8 == 0xFFFFFF00, but on a 64-bit machine, it equals 0xFFFFFFFF00. as such, doing 'and'
                // with 0xFFFFFFFF (or 0xFFFFFF00) on a 32-bit machine is unnecessary, but on a 64-bit machine, it is.
                $temp = (($temp << 8) & intval(0xFFFFFF00)) | (($temp >> 24) & 0x000000FF); // rotWord
                $temp = $this->_subWord($temp) ^ $rcon[$i / $this->Nk];
            } elseif ($this->Nk > 6 && $i % $this->Nk == 4) {
                $temp = $this->_subWord($temp);
            }
            $w[$i] = $w[$i - $this->Nk] ^ $temp;
        }

        // convert the key schedule from a vector of $Nb * ($Nr + 1) length to a matrix with $Nr + 1 rows and $Nb columns
        // and generate the inverse key schedule.  more specifically,
        // according to <http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf#page=23> (section 5.3.3),
        // "The key expansion for the Inverse Cipher is defined as follows:
        //        1. Apply the Key Expansion.
        //        2. Apply InvMixColumn to all Round Keys except the first and the last one."
        // also, see fips-197.pdf#page=27, "5.3.5 Equivalent Inverse Cipher"
        list($dt0, $dt1, $dt2, $dt3) = $this->_getInvTables();
        $temp = $this->w = $this->dw = array();
        for ($i = $row = $col = 0; $i < $length; $i++, $col++) {
            if ($col == $this->Nb) {
                if ($row == 0) {
                    $this->dw[0] = $this->w[0];
                } else {
                    // subWord + invMixColumn + invSubWord = invMixColumn
                    $j = 0;
                    while ($j < $this->Nb) {
                        $dw = $this->_subWord($this->w[$row][$j]);
                        $temp[$j] = $dt0[$dw >> 24 & 0x000000FF] ^
                                    $dt1[$dw >> 16 & 0x000000FF] ^
                                    $dt2[$dw >>  8 & 0x000000FF] ^
                                    $dt3[$dw       & 0x000000FF];
                        $j++;
                    }
                    $this->dw[$row] = $temp;
                }

                $col = 0;
                $row++;
            }
            $this->w[$row][$col] = $w[$i];
        }

        $this->dw[$row] = $this->w[$row];

        // Converting to 1-dim key arrays (both ascending)
        $this->dw = array_reverse($this->dw);
        $w  = array_pop($this->w);
        $dw = array_pop($this->dw);
        foreach ($this->w as $r => $wr) {
            foreach ($wr as $c => $wc) {
                $w[]  = $wc;
                $dw[] = $this->dw[$r][$c];
            }
        }
        $this->w  = $w;
        $this->dw = $dw;
    }

    /**
     * Performs S-Box substitutions
     *
     * @access private
     * @param int $word
     */
    function _subWord($word)
    {
        static $sbox;
        if (empty($sbox)) {
            list(, , , , $sbox) = $this->_getTables();
        }

        return  $sbox[$word       & 0x000000FF]        |
               ($sbox[$word >>  8 & 0x000000FF] <<  8) |
               ($sbox[$word >> 16 & 0x000000FF] << 16) |
               ($sbox[$word >> 24 & 0x000000FF] << 24);
    }

    /**
     * Provides the mixColumns and sboxes tables
     *
     * @see self::_encryptBlock()
     * @see self::_setupInlineCrypt()
     * @see self::_subWord()
     * @access private
     * @return array &$tables
     */
    function &_getTables()
    {
        static $tables;
        if (empty($tables)) {
            // according to <http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf#page=19> (section 5.2.1),
            // precomputed tables can be used in the mixColumns phase. in that example, they're assigned t0...t3, so
            // those are the names we'll use.
            $t3 = array_map('intval', array(
                // with array_map('intval', ...) we ensure we have only int's and not
                // some slower floats converted by php automatically on high values
                0x6363A5C6, 0x7C7C84F8, 0x777799EE, 0x7B7B8DF6, 0xF2F20DFF, 0x6B6BBDD6, 0x6F6FB1DE, 0xC5C55491,
                0x30305060, 0x01010302, 0x6767A9CE, 0x2B2B7D56, 0xFEFE19E7, 0xD7D762B5, 0xABABE64D, 0x76769AEC,
                0xCACA458F, 0x82829D1F, 0xC9C94089, 0x7D7D87FA, 0xFAFA15EF, 0x5959EBB2, 0x4747C98E, 0xF0F00BFB,
                0xADADEC41, 0xD4D467B3, 0xA2A2FD5F, 0xAFAFEA45, 0x9C9CBF23, 0xA4A4F753, 0x727296E4, 0xC0C05B9B,
                0xB7B7C275, 0xFDFD1CE1, 0x9393AE3D, 0x26266A4C, 0x36365A6C, 0x3F3F417E, 0xF7F702F5, 0xCCCC4F83,
                0x34345C68, 0xA5A5F451, 0xE5E534D1, 0xF1F108F9, 0x717193E2, 0xD8D873AB, 0x31315362, 0x15153F2A,
                0x04040C08, 0xC7C75295, 0x23236546, 0xC3C35E9D, 0x18182830, 0x9696A137, 0x05050F0A, 0x9A9AB52F,
                0x0707090E, 0x12123624, 0x80809B1B, 0xE2E23DDF, 0xEBEB26CD, 0x2727694E, 0xB2B2CD7F, 0x75759FEA,
                0x09091B12, 0x83839E1D, 0x2C2C7458, 0x1A1A2E34, 0x1B1B2D36, 0x6E6EB2DC, 0x5A5AEEB4, 0xA0A0FB5B,
                0x5252F6A4, 0x3B3B4D76, 0xD6D661B7, 0xB3B3CE7D, 0x29297B52, 0xE3E33EDD, 0x2F2F715E, 0x84849713,
                0x5353F5A6, 0xD1D168B9, 0x00000000, 0xEDED2CC1, 0x20206040, 0xFCFC1FE3, 0xB1B1C879, 0x5B5BEDB6,
                0x6A6ABED4, 0xCBCB468D, 0xBEBED967, 0x39394B72, 0x4A4ADE94, 0x4C4CD498, 0x5858E8B0, 0xCFCF4A85,
                0xD0D06BBB, 0xEFEF2AC5, 0xAAAAE54F, 0xFBFB16ED, 0x4343C586, 0x4D4DD79A, 0x33335566, 0x85859411,
                0x4545CF8A, 0xF9F910E9, 0x02020604, 0x7F7F81FE, 0x5050F0A0, 0x3C3C4478, 0x9F9FBA25, 0xA8A8E34B,
                0x5151F3A2, 0xA3A3FE5D, 0x4040C080, 0x8F8F8A05, 0x9292AD3F, 0x9D9DBC21, 0x38384870, 0xF5F504F1,
                0xBCBCDF63, 0xB6B6C177, 0xDADA75AF, 0x21216342, 0x10103020, 0xFFFF1AE5, 0xF3F30EFD, 0xD2D26DBF,
                0xCDCD4C81, 0x0C0C1418, 0x13133526, 0xECEC2FC3, 0x5F5FE1BE, 0x9797A235, 0x4444CC88, 0x1717392E,
                0xC4C45793, 0xA7A7F255, 0x7E7E82FC, 0x3D3D477A, 0x6464ACC8, 0x5D5DE7BA, 0x19192B32, 0x737395E6,
                0x6060A0C0, 0x81819819, 0x4F4FD19E, 0xDCDC7FA3, 0x22226644, 0x2A2A7E54, 0x9090AB3B, 0x8888830B,
                0x4646CA8C, 0xEEEE29C7, 0xB8B8D36B, 0x14143C28, 0xDEDE79A7, 0x5E5EE2BC, 0x0B0B1D16, 0xDBDB76AD,
                0xE0E03BDB, 0x32325664, 0x3A3A4E74, 0x0A0A1E14, 0x4949DB92, 0x06060A0C, 0x24246C48, 0x5C5CE4B8,
                0xC2C25D9F, 0xD3D36EBD, 0xACACEF43, 0x6262A6C4, 0x9191A839, 0x9595A431, 0xE4E437D3, 0x79798BF2,
                0xE7E732D5, 0xC8C8438B, 0x3737596E, 0x6D6DB7DA, 0x8D8D8C01, 0xD5D564B1, 0x4E4ED29C, 0xA9A9E049,
                0x6C6CB4D8, 0x5656FAAC, 0xF4F407F3, 0xEAEA25CF, 0x6565AFCA, 0x7A7A8EF4, 0xAEAEE947, 0x08081810,
                0xBABAD56F, 0x787888F0, 0x25256F4A, 0x2E2E725C, 0x1C1C2438, 0xA6A6F157, 0xB4B4C773, 0xC6C65197,
                0xE8E823CB, 0xDDDD7CA1, 0x74749CE8, 0x1F1F213E, 0x4B4BDD96, 0xBDBDDC61, 0x8B8B860D, 0x8A8A850F,
                0x707090E0, 0x3E3E427C, 0xB5B5C471, 0x6666AACC, 0x4848D890, 0x03030506, 0xF6F601F7, 0x0E0E121C,
                0x6161A3C2, 0x35355F6A, 0x5757F9AE, 0xB9B9D069, 0x86869117, 0xC1C15899, 0x1D1D273A, 0x9E9EB927,
                0xE1E138D9, 0xF8F813EB, 0x9898B32B, 0x11113322, 0x6969BBD2, 0xD9D970A9, 0x8E8E8907, 0x9494A733,
                0x9B9BB62D, 0x1E1E223C, 0x87879215, 0xE9E920C9, 0xCECE4987, 0x5555FFAA, 0x28287850, 0xDFDF7AA5,
                0x8C8C8F03, 0xA1A1F859, 0x89898009, 0x0D0D171A, 0xBFBFDA65, 0xE6E631D7, 0x4242C684, 0x6868B8D0,
                0x4141C382, 0x9999B029, 0x2D2D775A, 0x0F0F111E, 0xB0B0CB7B, 0x5454FCA8, 0xBBBBD66D, 0x16163A2C
            ));

            foreach ($t3 as $t3i) {
                $t0[] = (($t3i << 24) & intval(0xFF000000)) | (($t3i >>  8) & 0x00FFFFFF);
                $t1[] = (($t3i << 16) & intval(0xFFFF0000)) | (($t3i >> 16) & 0x0000FFFF);
                $t2[] = (($t3i <<  8) & intval(0xFFFFFF00)) | (($t3i >> 24) & 0x000000FF);
            }

            $tables = array(
                // The Precomputed mixColumns tables t0 - t3
                $t0,
                $t1,
                $t2,
                $t3,
                // The SubByte S-Box
                array(
                    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
                )
            );
        }
        return $tables;
    }

    /**
     * Provides the inverse mixColumns and inverse sboxes tables
     *
     * @see self::_decryptBlock()
     * @see self::_setupInlineCrypt()
     * @see self::_setupKey()
     * @access private
     * @return array &$tables
     */
    function &_getInvTables()
    {
        static $tables;
        if (empty($tables)) {
            $dt3 = array_map('intval', array(
                0xF4A75051, 0x4165537E, 0x17A4C31A, 0x275E963A, 0xAB6BCB3B, 0x9D45F11F, 0xFA58ABAC, 0xE303934B,
                0x30FA5520, 0x766DF6AD, 0xCC769188, 0x024C25F5, 0xE5D7FC4F, 0x2ACBD7C5, 0x35448026, 0x62A38FB5,
                0xB15A49DE, 0xBA1B6725, 0xEA0E9845, 0xFEC0E15D, 0x2F7502C3, 0x4CF01281, 0x4697A38D, 0xD3F9C66B,
                0x8F5FE703, 0x929C9515, 0x6D7AEBBF, 0x5259DA95, 0xBE832DD4, 0x7421D358, 0xE0692949, 0xC9C8448E,
                0xC2896A75, 0x8E7978F4, 0x583E6B99, 0xB971DD27, 0xE14FB6BE, 0x88AD17F0, 0x20AC66C9, 0xCE3AB47D,
                0xDF4A1863, 0x1A3182E5, 0x51336097, 0x537F4562, 0x6477E0B1, 0x6BAE84BB, 0x81A01CFE, 0x082B94F9,
                0x48685870, 0x45FD198F, 0xDE6C8794, 0x7BF8B752, 0x73D323AB, 0x4B02E272, 0x1F8F57E3, 0x55AB2A66,
                0xEB2807B2, 0xB5C2032F, 0xC57B9A86, 0x3708A5D3, 0x2887F230, 0xBFA5B223, 0x036ABA02, 0x16825CED,
                0xCF1C2B8A, 0x79B492A7, 0x07F2F0F3, 0x69E2A14E, 0xDAF4CD65, 0x05BED506, 0x34621FD1, 0xA6FE8AC4,
                0x2E539D34, 0xF355A0A2, 0x8AE13205, 0xF6EB75A4, 0x83EC390B, 0x60EFAA40, 0x719F065E, 0x6E1051BD,
                0x218AF93E, 0xDD063D96, 0x3E05AEDD, 0xE6BD464D, 0x548DB591, 0xC45D0571, 0x06D46F04, 0x5015FF60,
                0x98FB2419, 0xBDE997D6, 0x4043CC89, 0xD99E7767, 0xE842BDB0, 0x898B8807, 0x195B38E7, 0xC8EEDB79,
                0x7C0A47A1, 0x420FE97C, 0x841EC9F8, 0x00000000, 0x80868309, 0x2BED4832, 0x1170AC1E, 0x5A724E6C,
                0x0EFFFBFD, 0x8538560F, 0xAED51E3D, 0x2D392736, 0x0FD9640A, 0x5CA62168, 0x5B54D19B, 0x362E3A24,
                0x0A67B10C, 0x57E70F93, 0xEE96D2B4, 0x9B919E1B, 0xC0C54F80, 0xDC20A261, 0x774B695A, 0x121A161C,
                0x93BA0AE2, 0xA02AE5C0, 0x22E0433C, 0x1B171D12, 0x090D0B0E, 0x8BC7ADF2, 0xB6A8B92D, 0x1EA9C814,
                0xF1198557, 0x75074CAF, 0x99DDBBEE, 0x7F60FDA3, 0x01269FF7, 0x72F5BC5C, 0x663BC544, 0xFB7E345B,
                0x4329768B, 0x23C6DCCB, 0xEDFC68B6, 0xE4F163B8, 0x31DCCAD7, 0x63851042, 0x97224013, 0xC6112084,
                0x4A247D85, 0xBB3DF8D2, 0xF93211AE, 0x29A16DC7, 0x9E2F4B1D, 0xB230F3DC, 0x8652EC0D, 0xC1E3D077,
                0xB3166C2B, 0x70B999A9, 0x9448FA11, 0xE9642247, 0xFC8CC4A8, 0xF03F1AA0, 0x7D2CD856, 0x3390EF22,
                0x494EC787, 0x38D1C1D9, 0xCAA2FE8C, 0xD40B3698, 0xF581CFA6, 0x7ADE28A5, 0xB78E26DA, 0xADBFA43F,
                0x3A9DE42C, 0x78920D50, 0x5FCC9B6A, 0x7E466254, 0x8D13C2F6, 0xD8B8E890, 0x39F75E2E, 0xC3AFF582,
                0x5D80BE9F, 0xD0937C69, 0xD52DA96F, 0x2512B3CF, 0xAC993BC8, 0x187DA710, 0x9C636EE8, 0x3BBB7BDB,
                0x267809CD, 0x5918F46E, 0x9AB701EC, 0x4F9AA883, 0x956E65E6, 0xFFE67EAA, 0xBCCF0821, 0x15E8E6EF,
                0xE79BD9BA, 0x6F36CE4A, 0x9F09D4EA, 0xB07CD629, 0xA4B2AF31, 0x3F23312A, 0xA59430C6, 0xA266C035,
                0x4EBC3774, 0x82CAA6FC, 0x90D0B0E0, 0xA7D81533, 0x04984AF1, 0xECDAF741, 0xCD500E7F, 0x91F62F17,
                0x4DD68D76, 0xEFB04D43, 0xAA4D54CC, 0x9604DFE4, 0xD1B5E39E, 0x6A881B4C, 0x2C1FB8C1, 0x65517F46,
                0x5EEA049D, 0x8C355D01, 0x877473FA, 0x0B412EFB, 0x671D5AB3, 0xDBD25292, 0x105633E9, 0xD647136D,
                0xD7618C9A, 0xA10C7A37, 0xF8148E59, 0x133C89EB, 0xA927EECE, 0x61C935B7, 0x1CE5EDE1, 0x47B13C7A,
                0xD2DF599C, 0xF2733F55, 0x14CE7918, 0xC737BF73, 0xF7CDEA53, 0xFDAA5B5F, 0x3D6F14DF, 0x44DB8678,
                0xAFF381CA, 0x68C43EB9, 0x24342C38, 0xA3405FC2, 0x1DC37216, 0xE2250CBC, 0x3C498B28, 0x0D9541FF,
                0xA8017139, 0x0CB3DE08, 0xB4E49CD8, 0x56C19064, 0xCB84617B, 0x32B670D5, 0x6C5C7448, 0xB85742D0
            ));

            foreach ($dt3 as $dt3i) {
                $dt0[] = (($dt3i << 24) & intval(0xFF000000)) | (($dt3i >>  8) & 0x00FFFFFF);
                $dt1[] = (($dt3i << 16) & intval(0xFFFF0000)) | (($dt3i >> 16) & 0x0000FFFF);
                $dt2[] = (($dt3i <<  8) & intval(0xFFFFFF00)) | (($dt3i >> 24) & 0x000000FF);
            };

            $tables = array(
                // The Precomputed inverse mixColumns tables dt0 - dt3
                $dt0,
                $dt1,
                $dt2,
                $dt3,
                // The inverse SubByte S-Box
                array(
                    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
                )
            );
        }
        return $tables;
    }

    /**
     * Setup the performance-optimized function for de/encrypt()
     *
     * @see \phpseclib\Crypt\Base::_setupInlineCrypt()
     * @access private
     */
    function _setupInlineCrypt()
    {
        // Note: _setupInlineCrypt() will be called only if $this->changed === true
        // So here we are'nt under the same heavy timing-stress as we are in _de/encryptBlock() or de/encrypt().
        // However...the here generated function- $code, stored as php callback in $this->inline_crypt, must work as fast as even possible.

        $lambda_functions =& self::_getLambdaFunctions();

        // We create max. 10 hi-optimized code for memory reason. Means: For each $key one ultra fast inline-crypt function.
        // (Currently, for Crypt_Rijndael/AES, one generated $lambda_function cost on php5.5@32bit ~80kb unfreeable mem and ~130kb on php5.5@64bit)
        // After that, we'll still create very fast optimized code but not the hi-ultimative code, for each $mode one.
        $gen_hi_opt_code = (bool)(count($lambda_functions) < 10);

        // Generation of a uniqe hash for our generated code
        $code_hash = "Crypt_Rijndael, {$this->mode}, {$this->Nr}, {$this->Nb}";
        if ($gen_hi_opt_code) {
            $code_hash = str_pad($code_hash, 32) . $this->_hashInlineCryptFunction($this->key);
        }

        if (!isset($lambda_functions[$code_hash])) {
            switch (true) {
                case $gen_hi_opt_code:
                    // The hi-optimized $lambda_functions will use the key-words hardcoded for better performance.
                    $w  = $this->w;
                    $dw = $this->dw;
                    $init_encrypt = '';
                    $init_decrypt = '';
                    break;
                default:
                    for ($i = 0, $cw = count($this->w); $i < $cw; ++$i) {
                        $w[]  = '$w['  . $i . ']';
                        $dw[] = '$dw[' . $i . ']';
                    }
                    $init_encrypt = '$w  = $self->w;';
                    $init_decrypt = '$dw = $self->dw;';
            }

            $Nr = $this->Nr;
            $Nb = $this->Nb;
            $c  = $this->c;

            // Generating encrypt code:
            $init_encrypt.= '
                static $tables;
                if (empty($tables)) {
                    $tables = &$self->_getTables();
                }
                $t0   = $tables[0];
                $t1   = $tables[1];
                $t2   = $tables[2];
                $t3   = $tables[3];
                $sbox = $tables[4];
            ';

            $s  = 'e';
            $e  = 's';
            $wc = $Nb - 1;

            // Preround: addRoundKey
            $encrypt_block = '$in = unpack("N*", $in);'."\n";
            for ($i = 0; $i < $Nb; ++$i) {
                $encrypt_block .= '$s'.$i.' = $in['.($i + 1).'] ^ '.$w[++$wc].";\n";
            }

            // Mainrounds: shiftRows + subWord + mixColumns + addRoundKey
            for ($round = 1; $round < $Nr; ++$round) {
                list($s, $e) = array($e, $s);
                for ($i = 0; $i < $Nb; ++$i) {
                    $encrypt_block.=
                        '$'.$e.$i.' =
                        $t0[($'.$s.$i                  .' >> 24) & 0xff] ^
                        $t1[($'.$s.(($i + $c[1]) % $Nb).' >> 16) & 0xff] ^
                        $t2[($'.$s.(($i + $c[2]) % $Nb).' >>  8) & 0xff] ^
                        $t3[ $'.$s.(($i + $c[3]) % $Nb).'        & 0xff] ^
                        '.$w[++$wc].";\n";
                }
            }

            // Finalround: subWord + shiftRows + addRoundKey
            for ($i = 0; $i < $Nb; ++$i) {
                $encrypt_block.=
                    '$'.$e.$i.' =
                     $sbox[ $'.$e.$i.'        & 0xff]        |
                    ($sbox[($'.$e.$i.' >>  8) & 0xff] <<  8) |
                    ($sbox[($'.$e.$i.' >> 16) & 0xff] << 16) |
                    ($sbox[($'.$e.$i.' >> 24) & 0xff] << 24);'."\n";
            }
            $encrypt_block .= '$in = pack("N*"'."\n";
            for ($i = 0; $i < $Nb; ++$i) {
                $encrypt_block.= ',
                    ($'.$e.$i                  .' & '.((int)0xFF000000).') ^
                    ($'.$e.(($i + $c[1]) % $Nb).' &         0x00FF0000   ) ^
                    ($'.$e.(($i + $c[2]) % $Nb).' &         0x0000FF00   ) ^
                    ($'.$e.(($i + $c[3]) % $Nb).' &         0x000000FF   ) ^
                    '.$w[$i]."\n";
            }
            $encrypt_block .= ');';

            // Generating decrypt code:
            $init_decrypt.= '
                static $invtables;
                if (empty($invtables)) {
                    $invtables = &$self->_getInvTables();
                }
                $dt0   = $invtables[0];
                $dt1   = $invtables[1];
                $dt2   = $invtables[2];
                $dt3   = $invtables[3];
                $isbox = $invtables[4];
            ';

            $s  = 'e';
            $e  = 's';
            $wc = $Nb - 1;

            // Preround: addRoundKey
            $decrypt_block = '$in = unpack("N*", $in);'."\n";
            for ($i = 0; $i < $Nb; ++$i) {
                $decrypt_block .= '$s'.$i.' = $in['.($i + 1).'] ^ '.$dw[++$wc].';'."\n";
            }

            // Mainrounds: shiftRows + subWord + mixColumns + addRoundKey
            for ($round = 1; $round < $Nr; ++$round) {
                list($s, $e) = array($e, $s);
                for ($i = 0; $i < $Nb; ++$i) {
                    $decrypt_block.=
                        '$'.$e.$i.' =
                        $dt0[($'.$s.$i                        .' >> 24) & 0xff] ^
                        $dt1[($'.$s.(($Nb + $i - $c[1]) % $Nb).' >> 16) & 0xff] ^
                        $dt2[($'.$s.(($Nb + $i - $c[2]) % $Nb).' >>  8) & 0xff] ^
                        $dt3[ $'.$s.(($Nb + $i - $c[3]) % $Nb).'        & 0xff] ^
                        '.$dw[++$wc].";\n";
                }
            }

            // Finalround: subWord + shiftRows + addRoundKey
            for ($i = 0; $i < $Nb; ++$i) {
                $decrypt_block.=
                    '$'.$e.$i.' =
                     $isbox[ $'.$e.$i.'        & 0xff]        |
                    ($isbox[($'.$e.$i.' >>  8) & 0xff] <<  8) |
                    ($isbox[($'.$e.$i.' >> 16) & 0xff] << 16) |
                    ($isbox[($'.$e.$i.' >> 24) & 0xff] << 24);'."\n";
            }
            $decrypt_block .= '$in = pack("N*"'."\n";
            for ($i = 0; $i < $Nb; ++$i) {
                $decrypt_block.= ',
                    ($'.$e.$i.                        ' & '.((int)0xFF000000).') ^
                    ($'.$e.(($Nb + $i - $c[1]) % $Nb).' &         0x00FF0000   ) ^
                    ($'.$e.(($Nb + $i - $c[2]) % $Nb).' &         0x0000FF00   ) ^
                    ($'.$e.(($Nb + $i - $c[3]) % $Nb).' &         0x000000FF   ) ^
                    '.$dw[$i]."\n";
            }
            $decrypt_block .= ');';

            $lambda_functions[$code_hash] = $this->_createInlineCryptFunction(
                array(
                   'init_crypt'    => '',
                   'init_encrypt'  => $init_encrypt,
                   'init_decrypt'  => $init_decrypt,
                   'encrypt_block' => $encrypt_block,
                   'decrypt_block' => $decrypt_block
                )
            );
        }
        $this->inline_crypt = $lambda_functions[$code_hash];
    }
}


/**
 * Pure-PHP PKCS#1 (v2.1) compliant implementation of RSA.
 *
 * PHP version 5
 *
 * Here's an example of how to encrypt and decrypt text with this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $rsa = new \phpseclib\Crypt\RSA();
 *    extract($rsa->createKey());
 *
 *    $plaintext = 'terrafrost';
 *
 *    $rsa->loadKey($privatekey);
 *    $ciphertext = $rsa->encrypt($plaintext);
 *
 *    $rsa->loadKey($publickey);
 *    echo $rsa->decrypt($ciphertext);
 * ?>
 * </code>
 *
 * Here's an example of how to create signatures and verify signatures with this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $rsa = new \phpseclib\Crypt\RSA();
 *    extract($rsa->createKey());
 *
 *    $plaintext = 'terrafrost';
 *
 *    $rsa->loadKey($privatekey);
 *    $signature = $rsa->sign($plaintext);
 *
 *    $rsa->loadKey($publickey);
 *    echo $rsa->verify($plaintext, $signature) ? 'verified' : 'unverified';
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   RSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */


/**
 * Pure-PHP PKCS#1 compliant implementation of RSA.
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class KiboboCryptRSA
{
    /**#@+
     * @access public
     * @see self::encrypt()
     * @see self::decrypt()
     */
    /**
     * Use {@link http://en.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding Optimal Asymmetric Encryption Padding}
     * (OAEP) for encryption / decryption.
     *
     * Uses sha1 by default.
     *
     * @see self::setHash()
     * @see self::setMGFHash()
     */
    const ENCRYPTION_OAEP = 1;
    /**
     * Use PKCS#1 padding.
     *
     * Although self::ENCRYPTION_OAEP offers more security, including PKCS#1 padding is necessary for purposes of backwards
     * compatibility with protocols (like SSH-1) written before OAEP's introduction.
     */
    const ENCRYPTION_PKCS1 = 2;
    /**
     * Do not use any padding
     *
     * Although this method is not recommended it can none-the-less sometimes be useful if you're trying to decrypt some legacy
     * stuff, if you're trying to diagnose why an encrypted message isn't decrypting, etc.
     */
    const ENCRYPTION_NONE = 3;
    /**#@-*/

    /**#@+
     * @access public
     * @see self::sign()
     * @see self::verify()
     * @see self::setHash()
    */
    /**
     * Use the Probabilistic Signature Scheme for signing
     *
     * Uses sha1 by default.
     *
     * @see self::setSaltLength()
     * @see self::setMGFHash()
     */
    const SIGNATURE_PSS = 1;
    /**
     * Use the PKCS#1 scheme by default.
     *
     * Although self::SIGNATURE_PSS offers more security, including PKCS#1 signing is necessary for purposes of backwards
     * compatibility with protocols (like SSH-2) written before PSS's introduction.
     */
    const SIGNATURE_PKCS1 = 2;
    /**#@-*/

    /**#@+
     * @access private
     * @see \phpseclib\Crypt\RSA::createKey()
    */
    /**
     * ASN1 Integer
     */
    const ASN1_INTEGER = 2;
    /**
     * ASN1 Bit String
     */
    const ASN1_BITSTRING = 3;
    /**
     * ASN1 Octet String
     */
    const ASN1_OCTETSTRING = 4;
    /**
     * ASN1 Object Identifier
     */
    const ASN1_OBJECT = 6;
    /**
     * ASN1 Sequence (with the constucted bit set)
     */
    const ASN1_SEQUENCE = 48;
    /**#@-*/

    /**#@+
     * @access private
     * @see \phpseclib\Crypt\RSA::__construct()
    */
    /**
     * To use the pure-PHP implementation
     */
    const MODE_INTERNAL = 1;
    /**
     * To use the OpenSSL library
     *
     * (if enabled; otherwise, the internal implementation will be used)
     */
    const MODE_OPENSSL = 2;
    /**#@-*/

    /**#@+
     * @access public
     * @see \phpseclib\Crypt\RSA::createKey()
     * @see \phpseclib\Crypt\RSA::setPrivateKeyFormat()
    */
    /**
     * PKCS#1 formatted private key
     *
     * Used by OpenSSH
     */
    const PRIVATE_FORMAT_PKCS1 = 0;
    /**
     * PuTTY formatted private key
     */
    const PRIVATE_FORMAT_PUTTY = 1;
    /**
     * XML formatted private key
     */
    const PRIVATE_FORMAT_XML = 2;
    /**
     * PKCS#8 formatted private key
     */
    const PRIVATE_FORMAT_PKCS8 = 8;
    /**
     * OpenSSH formatted private key
     */
    const PRIVATE_FORMAT_OPENSSH = 9;
    /**#@-*/

    /**#@+
     * @access public
     * @see \phpseclib\Crypt\RSA::createKey()
     * @see \phpseclib\Crypt\RSA::setPublicKeyFormat()
    */
    /**
     * Raw public key
     *
     * An array containing two \phpseclib\Math\BigInteger objects.
     *
     * The exponent can be indexed with any of the following:
     *
     * 0, e, exponent, publicExponent
     *
     * The modulus can be indexed with any of the following:
     *
     * 1, n, modulo, modulus
     */
    const PUBLIC_FORMAT_RAW = 3;
    /**
     * PKCS#1 formatted public key (raw)
     *
     * Used by File/X509.php
     *
     * Has the following header:
     *
     * -----BEGIN RSA PUBLIC KEY-----
     *
     * Analogous to ssh-keygen's pem format (as specified by -m)
     */
    const PUBLIC_FORMAT_PKCS1 = 4;
    const PUBLIC_FORMAT_PKCS1_RAW = 4;
    /**
     * XML formatted public key
     */
    const PUBLIC_FORMAT_XML = 5;
    /**
     * OpenSSH formatted public key
     *
     * Place in $HOME/.ssh/authorized_keys
     */
    const PUBLIC_FORMAT_OPENSSH = 6;
    /**
     * PKCS#1 formatted public key (encapsulated)
     *
     * Used by PHP's openssl_public_encrypt() and openssl's rsautl (when -pubin is set)
     *
     * Has the following header:
     *
     * -----BEGIN PUBLIC KEY-----
     *
     * Analogous to ssh-keygen's pkcs8 format (as specified by -m). Although PKCS8
     * is specific to private keys it's basically creating a DER-encoded wrapper
     * for keys. This just extends that same concept to public keys (much like ssh-keygen)
     */
    const PUBLIC_FORMAT_PKCS8 = 7;
    /**#@-*/

    /**
     * Precomputed Zero
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    var $zero;

    /**
     * Precomputed One
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    var $one;

    /**
     * Private Key Format
     *
     * @var int
     * @access private
     */
    var $privateKeyFormat = self::PRIVATE_FORMAT_PKCS1;

    /**
     * Public Key Format
     *
     * @var int
     * @access public
     */
    var $publicKeyFormat = self::PUBLIC_FORMAT_PKCS8;

    /**
     * Modulus (ie. n)
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    var $modulus;

    /**
     * Modulus length
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    var $k;

    /**
     * Exponent (ie. e or d)
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    var $exponent;

    /**
     * Primes for Chinese Remainder Theorem (ie. p and q)
     *
     * @var array
     * @access private
     */
    var $primes;

    /**
     * Exponents for Chinese Remainder Theorem (ie. dP and dQ)
     *
     * @var array
     * @access private
     */
    var $exponents;

    /**
     * Coefficients for Chinese Remainder Theorem (ie. qInv)
     *
     * @var array
     * @access private
     */
    var $coefficients;

    /**
     * Hash name
     *
     * @var string
     * @access private
     */
    var $hashName;

    /**
     * Hash function
     *
     * @var \phpseclib\Crypt\Hash
     * @access private
     */
    var $hash;

    /**
     * Length of hash function output
     *
     * @var int
     * @access private
     */
    var $hLen;

    /**
     * Length of salt
     *
     * @var int
     * @access private
     */
    var $sLen;

    /**
     * Hash function for the Mask Generation Function
     *
     * @var \phpseclib\Crypt\Hash
     * @access private
     */
    var $mgfHash;

    /**
     * Length of MGF hash function output
     *
     * @var int
     * @access private
     */
    var $mgfHLen;

    /**
     * Encryption mode
     *
     * @var int
     * @access private
     */
    var $encryptionMode = self::ENCRYPTION_OAEP;

    /**
     * Signature mode
     *
     * @var int
     * @access private
     */
    var $signatureMode = self::SIGNATURE_PSS;

    /**
     * Public Exponent
     *
     * @var mixed
     * @access private
     */
    var $publicExponent = false;

    /**
     * Password
     *
     * @var string
     * @access private
     */
    var $password = false;

    /**
     * Components
     *
     * For use with parsing XML formatted keys.  PHP's XML Parser functions use utilized - instead of PHP's DOM functions -
     * because PHP's XML Parser functions work on PHP4 whereas PHP's DOM functions - although surperior - don't.
     *
     * @see self::_start_element_handler()
     * @var array
     * @access private
     */
    var $components = array();

    /**
     * Current String
     *
     * For use with parsing XML formatted keys.
     *
     * @see self::_character_handler()
     * @see self::_stop_element_handler()
     * @var mixed
     * @access private
     */
    var $current;

    /**
     * OpenSSL configuration file name.
     *
     * Set to null to use system configuration file.
     * @see self::createKey()
     * @var mixed
     * @Access public
     */
    var $configFile;

    /**
     * Public key comment field.
     *
     * @var string
     * @access private
     */
    var $comment = 'phpseclib-generated-key';

    /**
     * The constructor
     *
     * If you want to make use of the openssl extension, you'll need to set the mode manually, yourself.  The reason
     * \phpseclib\Crypt\RSA doesn't do it is because OpenSSL doesn't fail gracefully.  openssl_pkey_new(), in particular, requires
     * openssl.cnf be present somewhere and, unfortunately, the only real way to find out is too late.
     *
     * @return \phpseclib\Crypt\RSA
     * @access public
     */
    function __construct()
    {
        $this->configFile = dirname(__FILE__) . '/../openssl.cnf';

        if (!defined('CRYPT_RSA_MODE')) {
            switch (true) {
                // Math/BigInteger's openssl requirements are a little less stringent than Crypt/RSA's. in particular,
                // Math/BigInteger doesn't require an openssl.cfg file whereas Crypt/RSA does. so if Math/BigInteger
                // can't use OpenSSL it can be pretty trivially assumed, then, that Crypt/RSA can't either.
                case defined('MATH_BIGINTEGER_OPENSSL_DISABLE'):
                    define('CRYPT_RSA_MODE', self::MODE_INTERNAL);
                    break;
                case function_exists('phpinfo') && extension_loaded('openssl') && file_exists($this->configFile):
                    // some versions of XAMPP have mismatched versions of OpenSSL which causes it not to work
                    $versions = array();

                    // avoid generating errors (even with suppression) when phpinfo() is disabled (common in production systems)
                    if (strpos(ini_get('disable_functions'), 'phpinfo') === false) {
                        ob_start();
                        @phpinfo();
                        $content = ob_get_contents();
                        ob_end_clean();

                        preg_match_all('#OpenSSL (Header|Library) Version(.*)#im', $content, $matches);

                        if (!empty($matches[1])) {
                            for ($i = 0; $i < count($matches[1]); $i++) {
                                $fullVersion = trim(str_replace('=>', '', strip_tags($matches[2][$i])));

                                // Remove letter part in OpenSSL version
                                if (!preg_match('/(\d+\.\d+\.\d+)/i', $fullVersion, $m)) {
                                    $versions[$matches[1][$i]] = $fullVersion;
                                } else {
                                    $versions[$matches[1][$i]] = $m[0];
                                }
                            }
                        }
                    }

                    // it doesn't appear that OpenSSL versions were reported upon until PHP 5.3+
                    switch (true) {
                        case !isset($versions['Header']):
                        case !isset($versions['Library']):
                        case $versions['Header'] == $versions['Library']:
                        case version_compare($versions['Header'], '1.0.0') >= 0 && version_compare($versions['Library'], '1.0.0') >= 0:
                            define('CRYPT_RSA_MODE', self::MODE_OPENSSL);
                            break;
                        default:
                            define('CRYPT_RSA_MODE', self::MODE_INTERNAL);
                            define('MATH_BIGINTEGER_OPENSSL_DISABLE', true);
                    }
                    break;
                default:
                    define('CRYPT_RSA_MODE', self::MODE_INTERNAL);
            }
        }

        $this->zero = new KiboboCryptBigInteger();
        $this->one = new KiboboCryptBigInteger(1);

        $this->hash = new KiboboCryptHash('sha1');
        $this->hLen = $this->hash->getLength();
        $this->hashName = 'sha1';
        $this->mgfHash = new KiboboCryptHash('sha1');
        $this->mgfHLen = $this->mgfHash->getLength();
    }

    /**
     * Create public / private key pair
     *
     * Returns an array with the following three elements:
     *  - 'privatekey': The private key.
     *  - 'publickey':  The public key.
     *  - 'partialkey': A partially computed key (if the execution time exceeded $timeout).
     *                  Will need to be passed back to \phpseclib\Crypt\RSA::createKey() as the third parameter for further processing.
     *
     * @access public
     * @param int $bits
     * @param int $timeout
     * @param array $partial
     */
    function createKey($bits = 1024, $timeout = false, $partial = array())
    {
        if (!defined('CRYPT_RSA_EXPONENT')) {
            // http://en.wikipedia.org/wiki/65537_%28number%29
            define('CRYPT_RSA_EXPONENT', '65537');
        }
        // per <http://cseweb.ucsd.edu/~hovav/dist/survey.pdf#page=5>, this number ought not result in primes smaller
        // than 256 bits. as a consequence if the key you're trying to create is 1024 bits and you've set CRYPT_RSA_SMALLEST_PRIME
        // to 384 bits then you're going to get a 384 bit prime and a 640 bit prime (384 + 1024 % 384). at least if
        // CRYPT_RSA_MODE is set to self::MODE_INTERNAL. if CRYPT_RSA_MODE is set to self::MODE_OPENSSL then
        // CRYPT_RSA_SMALLEST_PRIME is ignored (ie. multi-prime RSA support is more intended as a way to speed up RSA key
        // generation when there's a chance neither gmp nor OpenSSL are installed)
        if (!defined('CRYPT_RSA_SMALLEST_PRIME')) {
            define('CRYPT_RSA_SMALLEST_PRIME', 4096);
        }

        // OpenSSL uses 65537 as the exponent and requires RSA keys be 384 bits minimum
        if (CRYPT_RSA_MODE == self::MODE_OPENSSL && $bits >= 384 && CRYPT_RSA_EXPONENT == 65537) {
            $config = array();
            if (isset($this->configFile)) {
                $config['config'] = $this->configFile;
            }
            $rsa = openssl_pkey_new(array('private_key_bits' => $bits) + $config);
            openssl_pkey_export($rsa, $privatekey, null, $config);
            $publickey = openssl_pkey_get_details($rsa);
            $publickey = $publickey['key'];

            $privatekey = call_user_func_array(array($this, '_convertPrivateKey'), array_values($this->_parseKey($privatekey, self::PRIVATE_FORMAT_PKCS1)));
            $publickey = call_user_func_array(array($this, '_convertPublicKey'), array_values($this->_parseKey($publickey, self::PUBLIC_FORMAT_PKCS1)));

            // clear the buffer of error strings stemming from a minimalistic openssl.cnf
            while (openssl_error_string() !== false) {
            }

            return array(
                'privatekey' => $privatekey,
                'publickey' => $publickey,
                'partialkey' => false
            );
        }

        static $e;
        if (!isset($e)) {
            $e = new KiboboCryptBigInteger(CRYPT_RSA_EXPONENT);
        }

        extract($this->_generateMinMax($bits));
        $absoluteMin = $min;
        $temp = $bits >> 1; // divide by two to see how many bits P and Q would be
        if ($temp > CRYPT_RSA_SMALLEST_PRIME) {
            $num_primes = floor($bits / CRYPT_RSA_SMALLEST_PRIME);
            $temp = CRYPT_RSA_SMALLEST_PRIME;
        } else {
            $num_primes = 2;
        }
        extract($this->_generateMinMax($temp + $bits % $temp));
        $finalMax = $max;
        extract($this->_generateMinMax($temp));

        $generator = new KiboboCryptBigInteger();

        $n = $this->one->copy();
        if (!empty($partial)) {
            extract(unserialize($partial));
        } else {
            $exponents = $coefficients = $primes = array();
            $lcm = array(
                'top' => $this->one->copy(),
                'bottom' => false
            );
        }

        $start = time();
        $i0 = count($primes) + 1;

        do {
            for ($i = $i0; $i <= $num_primes; $i++) {
                if ($timeout !== false) {
                    $timeout-= time() - $start;
                    $start = time();
                    if ($timeout <= 0) {
                        return array(
                            'privatekey' => '',
                            'publickey'  => '',
                            'partialkey' => serialize(array(
                                'primes' => $primes,
                                'coefficients' => $coefficients,
                                'lcm' => $lcm,
                                'exponents' => $exponents
                            ))
                        );
                    }
                }

                if ($i == $num_primes) {
                    list($min, $temp) = $absoluteMin->divide($n);
                    if (!$temp->equals($this->zero)) {
                        $min = $min->add($this->one); // ie. ceil()
                    }
                    $primes[$i] = $generator->randomPrime($min, $finalMax, $timeout);
                } else {
                    $primes[$i] = $generator->randomPrime($min, $max, $timeout);
                }

                if ($primes[$i] === false) { // if we've reached the timeout
                    if (count($primes) > 1) {
                        $partialkey = '';
                    } else {
                        array_pop($primes);
                        $partialkey = serialize(array(
                            'primes' => $primes,
                            'coefficients' => $coefficients,
                            'lcm' => $lcm,
                            'exponents' => $exponents
                        ));
                    }

                    return array(
                        'privatekey' => '',
                        'publickey'  => '',
                        'partialkey' => $partialkey
                    );
                }

                // the first coefficient is calculated differently from the rest
                // ie. instead of being $primes[1]->modInverse($primes[2]), it's $primes[2]->modInverse($primes[1])
                if ($i > 2) {
                    $coefficients[$i] = $n->modInverse($primes[$i]);
                }

                $n = $n->multiply($primes[$i]);

                $temp = $primes[$i]->subtract($this->one);

                // textbook RSA implementations use Euler's totient function instead of the least common multiple.
                // see http://en.wikipedia.org/wiki/Euler%27s_totient_function
                $lcm['top'] = $lcm['top']->multiply($temp);
                $lcm['bottom'] = $lcm['bottom'] === false ? $temp : $lcm['bottom']->gcd($temp);

                $exponents[$i] = $e->modInverse($temp);
            }

            list($temp) = $lcm['top']->divide($lcm['bottom']);
            $gcd = $temp->gcd($e);
            $i0 = 1;
        } while (!$gcd->equals($this->one));

        $d = $e->modInverse($temp);

        $coefficients[2] = $primes[2]->modInverse($primes[1]);

        // from <http://tools.ietf.org/html/rfc3447#appendix-A.1.2>:
        // RSAPrivateKey ::= SEQUENCE {
        //     version           Version,
        //     modulus           INTEGER,  -- n
        //     publicExponent    INTEGER,  -- e
        //     privateExponent   INTEGER,  -- d
        //     prime1            INTEGER,  -- p
        //     prime2            INTEGER,  -- q
        //     exponent1         INTEGER,  -- d mod (p-1)
        //     exponent2         INTEGER,  -- d mod (q-1)
        //     coefficient       INTEGER,  -- (inverse of q) mod p
        //     otherPrimeInfos   OtherPrimeInfos OPTIONAL
        // }

        return array(
            'privatekey' => $this->_convertPrivateKey($n, $e, $d, $primes, $exponents, $coefficients),
            'publickey'  => $this->_convertPublicKey($n, $e),
            'partialkey' => false
        );
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @access private
     * @see self::setPrivateKeyFormat()
     * @param Math_BigInteger $n
     * @param Math_BigInteger $e
     * @param Math_BigInteger $d
     * @param array<int,Math_BigInteger> $primes
     * @param array<int,Math_BigInteger> $exponents
     * @param array<int,Math_BigInteger> $coefficients
     * @return string
     */
    function _convertPrivateKey($n, $e, $d, $primes, $exponents, $coefficients)
    {
        $signed = $this->privateKeyFormat != self::PRIVATE_FORMAT_XML;
        $num_primes = count($primes);
        $raw = array(
            'version' => $num_primes == 2 ? chr(0) : chr(1), // two-prime vs. multi
            'modulus' => $n->toBytes($signed),
            'publicExponent' => $e->toBytes($signed),
            'privateExponent' => $d->toBytes($signed),
            'prime1' => $primes[1]->toBytes($signed),
            'prime2' => $primes[2]->toBytes($signed),
            'exponent1' => $exponents[1]->toBytes($signed),
            'exponent2' => $exponents[2]->toBytes($signed),
            'coefficient' => $coefficients[2]->toBytes($signed)
        );

        // if the format in question does not support multi-prime rsa and multi-prime rsa was used,
        // call _convertPublicKey() instead.
        switch ($this->privateKeyFormat) {
            case self::PRIVATE_FORMAT_XML:
                if ($num_primes != 2) {
                    return false;
                }
                return "<RSAKeyValue>\r\n" .
                       '  <Modulus>' . base64_encode($raw['modulus']) . "</Modulus>\r\n" .
                       '  <Exponent>' . base64_encode($raw['publicExponent']) . "</Exponent>\r\n" .
                       '  <P>' . base64_encode($raw['prime1']) . "</P>\r\n" .
                       '  <Q>' . base64_encode($raw['prime2']) . "</Q>\r\n" .
                       '  <DP>' . base64_encode($raw['exponent1']) . "</DP>\r\n" .
                       '  <DQ>' . base64_encode($raw['exponent2']) . "</DQ>\r\n" .
                       '  <InverseQ>' . base64_encode($raw['coefficient']) . "</InverseQ>\r\n" .
                       '  <D>' . base64_encode($raw['privateExponent']) . "</D>\r\n" .
                       '</RSAKeyValue>';
                break;
            case self::PRIVATE_FORMAT_PUTTY:
                if ($num_primes != 2) {
                    return false;
                }
                $key = "PuTTY-User-Key-File-2: ssh-rsa\r\nEncryption: ";
                $encryption = (!empty($this->password) || is_string($this->password)) ? 'aes256-cbc' : 'none';
                $key.= $encryption;
                $key.= "\r\nComment: " . $this->comment . "\r\n";
                $public = pack(
                    'Na*Na*Na*',
                    strlen('ssh-rsa'),
                    'ssh-rsa',
                    strlen($raw['publicExponent']),
                    $raw['publicExponent'],
                    strlen($raw['modulus']),
                    $raw['modulus']
                );
                $source = pack(
                    'Na*Na*Na*Na*',
                    strlen('ssh-rsa'),
                    'ssh-rsa',
                    strlen($encryption),
                    $encryption,
                    strlen($this->comment),
                    $this->comment,
                    strlen($public),
                    $public
                );
                $public = base64_encode($public);
                $key.= "Public-Lines: " . ((strlen($public) + 63) >> 6) . "\r\n";
                $key.= chunk_split($public, 64);
                $private = pack(
                    'Na*Na*Na*Na*',
                    strlen($raw['privateExponent']),
                    $raw['privateExponent'],
                    strlen($raw['prime1']),
                    $raw['prime1'],
                    strlen($raw['prime2']),
                    $raw['prime2'],
                    strlen($raw['coefficient']),
                    $raw['coefficient']
                );
                if (empty($this->password) && !is_string($this->password)) {
                    $source.= pack('Na*', strlen($private), $private);
                    $hashkey = 'putty-private-key-file-mac-key';
                } else {
                    $private.= Random::string(16 - (strlen($private) & 15));
                    $source.= pack('Na*', strlen($private), $private);
                    $sequence = 0;
                    $symkey = '';
                    while (strlen($symkey) < 32) {
                        $temp = pack('Na*', $sequence++, $this->password);
                        $symkey.= pack('H*', sha1($temp));
                    }
                    $symkey = substr($symkey, 0, 32);
                    $crypto = new KiboboCryptAES();

                    $crypto->setKey($symkey);
                    $crypto->disablePadding();
                    $private = $crypto->encrypt($private);
                    $hashkey = 'putty-private-key-file-mac-key' . $this->password;
                }

                $private = base64_encode($private);
                $key.= 'Private-Lines: ' . ((strlen($private) + 63) >> 6) . "\r\n";
                $key.= chunk_split($private, 64);
                $hash = new KiboboCryptHash('sha1');
                $hash->setKey(pack('H*', sha1($hashkey)));
                $key.= 'Private-MAC: ' . bin2hex($hash->hash($source)) . "\r\n";

                return $key;
            case self::PRIVATE_FORMAT_OPENSSH:
                if ($num_primes != 2) {
                    return false;
                }
                $publicKey = pack('Na*Na*Na*', strlen('ssh-rsa'), 'ssh-rsa', strlen($raw['publicExponent']), $raw['publicExponent'], strlen($raw['modulus']), $raw['modulus']);
                $privateKey = pack(
                    'Na*Na*Na*Na*Na*Na*Na*',
                    strlen('ssh-rsa'),
                    'ssh-rsa',
                    strlen($raw['modulus']),
                    $raw['modulus'],
                    strlen($raw['publicExponent']),
                    $raw['publicExponent'],
                    strlen($raw['privateExponent']),
                    $raw['privateExponent'],
                    strlen($raw['coefficient']),
                    $raw['coefficient'],
                    strlen($raw['prime1']),
                    $raw['prime1'],
                    strlen($raw['prime2']),
                    $raw['prime2']
                );
                $checkint = Random::string(4);
                $paddedKey = pack(
                    'a*Na*',
                    $checkint . $checkint . $privateKey,
                    strlen($this->comment),
                    $this->comment
                );
                $paddingLength = (7 * strlen($paddedKey)) % 8;
                for ($i = 1; $i <= $paddingLength; $i++) {
                    $paddedKey.= chr($i);
                }
                $key = pack(
                    'Na*Na*Na*NNa*Na*',
                    strlen('none'),
                    'none',
                    strlen('none'),
                    'none',
                    0,
                    '',
                    1,
                    strlen($publicKey),
                    $publicKey,
                    strlen($paddedKey),
                    $paddedKey
                );
                $key = "openssh-key-v1\0$key";

                return "-----BEGIN OPENSSH PRIVATE KEY-----\n" .
                       chunk_split(base64_encode($key), 70, "\n") .
                       "-----END OPENSSH PRIVATE KEY-----\n";
            default: // eg. self::PRIVATE_FORMAT_PKCS1
                $components = array();
                foreach ($raw as $name => $value) {
                    $components[$name] = pack('Ca*a*', self::ASN1_INTEGER, $this->_encodeLength(strlen($value)), $value);
                }

                $RSAPrivateKey = implode('', $components);

                if ($num_primes > 2) {
                    $OtherPrimeInfos = '';
                    for ($i = 3; $i <= $num_primes; $i++) {
                        // OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
                        //
                        // OtherPrimeInfo ::= SEQUENCE {
                        //     prime             INTEGER,  -- ri
                        //     exponent          INTEGER,  -- di
                        //     coefficient       INTEGER   -- ti
                        // }
                        $OtherPrimeInfo = pack('Ca*a*', self::ASN1_INTEGER, $this->_encodeLength(strlen($primes[$i]->toBytes(true))), $primes[$i]->toBytes(true));
                        $OtherPrimeInfo.= pack('Ca*a*', self::ASN1_INTEGER, $this->_encodeLength(strlen($exponents[$i]->toBytes(true))), $exponents[$i]->toBytes(true));
                        $OtherPrimeInfo.= pack('Ca*a*', self::ASN1_INTEGER, $this->_encodeLength(strlen($coefficients[$i]->toBytes(true))), $coefficients[$i]->toBytes(true));
                        $OtherPrimeInfos.= pack('Ca*a*', self::ASN1_SEQUENCE, $this->_encodeLength(strlen($OtherPrimeInfo)), $OtherPrimeInfo);
                    }
                    $RSAPrivateKey.= pack('Ca*a*', self::ASN1_SEQUENCE, $this->_encodeLength(strlen($OtherPrimeInfos)), $OtherPrimeInfos);
                }

                $RSAPrivateKey = pack('Ca*a*', self::ASN1_SEQUENCE, $this->_encodeLength(strlen($RSAPrivateKey)), $RSAPrivateKey);

                if ($this->privateKeyFormat == self::PRIVATE_FORMAT_PKCS8) {
                    $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
                    $RSAPrivateKey = pack(
                        'Ca*a*Ca*a*',
                        self::ASN1_INTEGER,
                        "\01\00",
                        $rsaOID,
                        4,
                        $this->_encodeLength(strlen($RSAPrivateKey)),
                        $RSAPrivateKey
                    );
                    $RSAPrivateKey = pack('Ca*a*', self::ASN1_SEQUENCE, $this->_encodeLength(strlen($RSAPrivateKey)), $RSAPrivateKey);
                    if (!empty($this->password) || is_string($this->password)) {
                        $salt = Random::string(8);
                        $iterationCount = 2048;

                        $crypto = new DES();
                        $crypto->setPassword($this->password, 'pbkdf1', 'md5', $salt, $iterationCount);
                        $RSAPrivateKey = $crypto->encrypt($RSAPrivateKey);

                        $parameters = pack(
                            'Ca*a*Ca*N',
                            self::ASN1_OCTETSTRING,
                            $this->_encodeLength(strlen($salt)),
                            $salt,
                            self::ASN1_INTEGER,
                            $this->_encodeLength(4),
                            $iterationCount
                        );
                        $pbeWithMD5AndDES_CBC = "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x03";

                        $encryptionAlgorithm = pack(
                            'Ca*a*Ca*a*',
                            self::ASN1_OBJECT,
                            $this->_encodeLength(strlen($pbeWithMD5AndDES_CBC)),
                            $pbeWithMD5AndDES_CBC,
                            self::ASN1_SEQUENCE,
                            $this->_encodeLength(strlen($parameters)),
                            $parameters
                        );

                        $RSAPrivateKey = pack(
                            'Ca*a*Ca*a*',
                            self::ASN1_SEQUENCE,
                            $this->_encodeLength(strlen($encryptionAlgorithm)),
                            $encryptionAlgorithm,
                            self::ASN1_OCTETSTRING,
                            $this->_encodeLength(strlen($RSAPrivateKey)),
                            $RSAPrivateKey
                        );

                        $RSAPrivateKey = pack('Ca*a*', self::ASN1_SEQUENCE, $this->_encodeLength(strlen($RSAPrivateKey)), $RSAPrivateKey);

                        $RSAPrivateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n" .
                                         chunk_split(base64_encode($RSAPrivateKey), 64) .
                                         '-----END ENCRYPTED PRIVATE KEY-----';
                    } else {
                        $RSAPrivateKey = "-----BEGIN PRIVATE KEY-----\r\n" .
                                         chunk_split(base64_encode($RSAPrivateKey), 64) .
                                         '-----END PRIVATE KEY-----';
                    }
                    return $RSAPrivateKey;
                }

                if (!empty($this->password) || is_string($this->password)) {
                    $iv = Random::string(8);
                    $symkey = pack('H*', md5($this->password . $iv)); // symkey is short for symmetric key
                    $symkey.= substr(pack('H*', md5($symkey . $this->password . $iv)), 0, 8);
                    $des = new TripleDES();
                    $des->setKey($symkey);
                    $des->setIV($iv);
                    $iv = strtoupper(bin2hex($iv));
                    $RSAPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\r\n" .
                                     "Proc-Type: 4,ENCRYPTED\r\n" .
                                     "DEK-Info: DES-EDE3-CBC,$iv\r\n" .
                                     "\r\n" .
                                     chunk_split(base64_encode($des->encrypt($RSAPrivateKey)), 64) .
                                     '-----END RSA PRIVATE KEY-----';
                } else {
                    $RSAPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\r\n" .
                                     chunk_split(base64_encode($RSAPrivateKey), 64) .
                                     '-----END RSA PRIVATE KEY-----';
                }

                return $RSAPrivateKey;
        }
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @access private
     * @see self::setPublicKeyFormat()
     * @param Math_BigInteger $n
     * @param Math_BigInteger $e
     * @return string|array<string,Math_BigInteger>
     */
    function _convertPublicKey($n, $e)
    {
        $signed = $this->publicKeyFormat != self::PUBLIC_FORMAT_XML;

        $modulus = $n->toBytes($signed);
        $publicExponent = $e->toBytes($signed);

        switch ($this->publicKeyFormat) {
            case self::PUBLIC_FORMAT_RAW:
                return array('e' => $e->copy(), 'n' => $n->copy());
            case self::PUBLIC_FORMAT_XML:
                return "<RSAKeyValue>\r\n" .
                       '  <Modulus>' . base64_encode($modulus) . "</Modulus>\r\n" .
                       '  <Exponent>' . base64_encode($publicExponent) . "</Exponent>\r\n" .
                       '</RSAKeyValue>';
                break;
            case self::PUBLIC_FORMAT_OPENSSH:
                // from <http://tools.ietf.org/html/rfc4253#page-15>:
                // string    "ssh-rsa"
                // mpint     e
                // mpint     n
                $RSAPublicKey = pack('Na*Na*Na*', strlen('ssh-rsa'), 'ssh-rsa', strlen($publicExponent), $publicExponent, strlen($modulus), $modulus);
                $RSAPublicKey = 'ssh-rsa ' . base64_encode($RSAPublicKey) . ' ' . $this->comment;

                return $RSAPublicKey;
            default: // eg. self::PUBLIC_FORMAT_PKCS1_RAW or self::PUBLIC_FORMAT_PKCS1
                // from <http://tools.ietf.org/html/rfc3447#appendix-A.1.1>:
                // RSAPublicKey ::= SEQUENCE {
                //     modulus           INTEGER,  -- n
                //     publicExponent    INTEGER   -- e
                // }
                $components = array(
                    'modulus' => pack('Ca*a*', self::ASN1_INTEGER, $this->_encodeLength(strlen($modulus)), $modulus),
                    'publicExponent' => pack('Ca*a*', self::ASN1_INTEGER, $this->_encodeLength(strlen($publicExponent)), $publicExponent)
                );

                $RSAPublicKey = pack(
                    'Ca*a*a*',
                    self::ASN1_SEQUENCE,
                    $this->_encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
                    $components['modulus'],
                    $components['publicExponent']
                );

                if ($this->publicKeyFormat == self::PUBLIC_FORMAT_PKCS1_RAW) {
                    $RSAPublicKey = "-----BEGIN RSA PUBLIC KEY-----\r\n" .
                                    chunk_split(base64_encode($RSAPublicKey), 64) .
                                    '-----END RSA PUBLIC KEY-----';
                } else {
                    // sequence(oid(1.2.840.113549.1.1.1), null)) = rsaEncryption.
                    $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
                    $RSAPublicKey = chr(0) . $RSAPublicKey;
                    $RSAPublicKey = chr(3) . $this->_encodeLength(strlen($RSAPublicKey)) . $RSAPublicKey;

                    $RSAPublicKey = pack(
                        'Ca*a*',
                        self::ASN1_SEQUENCE,
                        $this->_encodeLength(strlen($rsaOID . $RSAPublicKey)),
                        $rsaOID . $RSAPublicKey
                    );

                    $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
                                     chunk_split(base64_encode($RSAPublicKey), 64) .
                                     '-----END PUBLIC KEY-----';
                }

                return $RSAPublicKey;
        }
    }

    /**
     * Break a public or private key down into its constituant components
     *
     * @access private
     * @see self::_convertPublicKey()
     * @see self::_convertPrivateKey()
     * @param string|array $key
     * @param int $type
     * @return array|bool
     */
    function _parseKey($key, $type)
    {
        if ($type != self::PUBLIC_FORMAT_RAW && !is_string($key)) {
            return false;
        }

        switch ($type) {
            case self::PUBLIC_FORMAT_RAW:
                if (!is_array($key)) {
                    return false;
                }
                $components = array();
                switch (true) {
                    case isset($key['e']):
                        $components['publicExponent'] = $key['e']->copy();
                        break;
                    case isset($key['exponent']):
                        $components['publicExponent'] = $key['exponent']->copy();
                        break;
                    case isset($key['publicExponent']):
                        $components['publicExponent'] = $key['publicExponent']->copy();
                        break;
                    case isset($key[0]):
                        $components['publicExponent'] = $key[0]->copy();
                }
                switch (true) {
                    case isset($key['n']):
                        $components['modulus'] = $key['n']->copy();
                        break;
                    case isset($key['modulo']):
                        $components['modulus'] = $key['modulo']->copy();
                        break;
                    case isset($key['modulus']):
                        $components['modulus'] = $key['modulus']->copy();
                        break;
                    case isset($key[1]):
                        $components['modulus'] = $key[1]->copy();
                }
                return isset($components['modulus']) && isset($components['publicExponent']) ? $components : false;
            case self::PRIVATE_FORMAT_PKCS1:
            case self::PRIVATE_FORMAT_PKCS8:
            case self::PUBLIC_FORMAT_PKCS1:
                /* Although PKCS#1 proposes a format that public and private keys can use, encrypting them is
                   "outside the scope" of PKCS#1.  PKCS#1 then refers you to PKCS#12 and PKCS#15 if you're wanting to
                   protect private keys, however, that's not what OpenSSL* does.  OpenSSL protects private keys by adding
                   two new "fields" to the key - DEK-Info and Proc-Type.  These fields are discussed here:

                   http://tools.ietf.org/html/rfc1421#section-4.6.1.1
                   http://tools.ietf.org/html/rfc1421#section-4.6.1.3

                   DES-EDE3-CBC as an algorithm, however, is not discussed anywhere, near as I can tell.
                   DES-CBC and DES-EDE are discussed in RFC1423, however, DES-EDE3-CBC isn't, nor is its key derivation
                   function.  As is, the definitive authority on this encoding scheme isn't the IETF but rather OpenSSL's
                   own implementation.  ie. the implementation *is* the standard and any bugs that may exist in that
                   implementation are part of the standard, as well.

                   * OpenSSL is the de facto standard.  It's utilized by OpenSSH and other projects */
                if (preg_match('#DEK-Info: (.+),(.+)#', $key, $matches)) {
                    $iv = pack('H*', trim($matches[2]));
                    $symkey = pack('H*', md5($this->password . substr($iv, 0, 8))); // symkey is short for symmetric key
                    $symkey.= pack('H*', md5($symkey . $this->password . substr($iv, 0, 8)));
                    // remove the Proc-Type / DEK-Info sections as they're no longer needed
                    $key = preg_replace('#^(?:Proc-Type|DEK-Info): .*#m', '', $key);
                    $ciphertext = $this->_extractBER($key);
                    if ($ciphertext === false) {
                        $ciphertext = $key;
                    }
                    switch ($matches[1]) {
                        case 'AES-256-CBC':
                            $crypto = new KiboboCryptAES();
                            break;
                        case 'AES-128-CBC':
                            $symkey = substr($symkey, 0, 16);
                            $crypto = new KiboboCryptAES();
                            break;
                        case 'DES-EDE3-CFB':
                            $crypto = new TripleDES(KiboboCryptBase::MODE_CFB);
                            break;
                        case 'DES-EDE3-CBC':
                            $symkey = substr($symkey, 0, 24);
                            $crypto = new TripleDES();
                            break;
                        case 'DES-CBC':
                            $crypto = new DES();
                            break;
                        default:
                            return false;
                    }
                    $crypto->setKey($symkey);
                    $crypto->setIV($iv);
                    $decoded = $crypto->decrypt($ciphertext);
                } else {
                    $decoded = $this->_extractBER($key);
                }

                if ($decoded !== false) {
                    $key = $decoded;
                }

                $components = array();

                if (ord($this->_string_shift($key)) != self::ASN1_SEQUENCE) {
                    return false;
                }
                if ($this->_decodeLength($key) != strlen($key)) {
                    return false;
                }

                $tag = ord($this->_string_shift($key));
                /* intended for keys for which OpenSSL's asn1parse returns the following:

                    0:d=0  hl=4 l= 631 cons: SEQUENCE
                    4:d=1  hl=2 l=   1 prim:  INTEGER           :00
                    7:d=1  hl=2 l=  13 cons:  SEQUENCE
                    9:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
                   20:d=2  hl=2 l=   0 prim:   NULL
                   22:d=1  hl=4 l= 609 prim:  OCTET STRING

                   ie. PKCS8 keys*/

                if ($tag == self::ASN1_INTEGER && substr($key, 0, 3) == "\x01\x00\x30") {
                    $this->_string_shift($key, 3);
                    $tag = self::ASN1_SEQUENCE;
                }

                if ($tag == self::ASN1_SEQUENCE) {
                    $temp = $this->_string_shift($key, $this->_decodeLength($key));
                    if (ord($this->_string_shift($temp)) != self::ASN1_OBJECT) {
                        return false;
                    }
                    $length = $this->_decodeLength($temp);
                    switch ($this->_string_shift($temp, $length)) {
                        case "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01": // rsaEncryption
                        case "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0A": // rsaPSS
                            break;
                        case "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x03": // pbeWithMD5AndDES-CBC
                            /*
                               PBEParameter ::= SEQUENCE {
                                   salt OCTET STRING (SIZE(8)),
                                   iterationCount INTEGER }
                            */
                            if (ord($this->_string_shift($temp)) != self::ASN1_SEQUENCE) {
                                return false;
                            }
                            if ($this->_decodeLength($temp) != strlen($temp)) {
                                return false;
                            }
                            $this->_string_shift($temp); // assume it's an octet string
                            $salt = $this->_string_shift($temp, $this->_decodeLength($temp));
                            if (ord($this->_string_shift($temp)) != self::ASN1_INTEGER) {
                                return false;
                            }
                            $this->_decodeLength($temp);
                            list(, $iterationCount) = unpack('N', str_pad($temp, 4, chr(0), STR_PAD_LEFT));
                            $this->_string_shift($key); // assume it's an octet string
                            $length = $this->_decodeLength($key);
                            if (strlen($key) != $length) {
                                return false;
                            }

                            $crypto = new DES();
                            $crypto->setPassword($this->password, 'pbkdf1', 'md5', $salt, $iterationCount);
                            $key = $crypto->decrypt($key);
                            if ($key === false) {
                                return false;
                            }
                            return $this->_parseKey($key, self::PRIVATE_FORMAT_PKCS1);
                        default:
                            return false;
                    }
                    /* intended for keys for which OpenSSL's asn1parse returns the following:

                        0:d=0  hl=4 l= 290 cons: SEQUENCE
                        4:d=1  hl=2 l=  13 cons:  SEQUENCE
                        6:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
                       17:d=2  hl=2 l=   0 prim:   NULL
                       19:d=1  hl=4 l= 271 prim:  BIT STRING */
                    $tag = ord($this->_string_shift($key)); // skip over the BIT STRING / OCTET STRING tag
                    $this->_decodeLength($key); // skip over the BIT STRING / OCTET STRING length
                    // "The initial octet shall encode, as an unsigned binary integer wtih bit 1 as the least significant bit, the number of
                    //  unused bits in the final subsequent octet. The number shall be in the range zero to seven."
                    //  -- http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf (section 8.6.2.2)
                    if ($tag == self::ASN1_BITSTRING) {
                        $this->_string_shift($key);
                    }
                    if (ord($this->_string_shift($key)) != self::ASN1_SEQUENCE) {
                        return false;
                    }
                    if ($this->_decodeLength($key) != strlen($key)) {
                        return false;
                    }
                    $tag = ord($this->_string_shift($key));
                }
                if ($tag != self::ASN1_INTEGER) {
                    return false;
                }

                $length = $this->_decodeLength($key);
                $temp = $this->_string_shift($key, $length);
                if (strlen($temp) != 1 || ord($temp) > 2) {
                    $components['modulus'] = new KiboboCryptBigInteger($temp, 256);
                    $this->_string_shift($key); // skip over self::ASN1_INTEGER
                    $length = $this->_decodeLength($key);
                    $components[$type == self::PUBLIC_FORMAT_PKCS1 ? 'publicExponent' : 'privateExponent'] = new KiboboCryptBigInteger($this->_string_shift($key, $length), 256);

                    return $components;
                }
                if (ord($this->_string_shift($key)) != self::ASN1_INTEGER) {
                    return false;
                }
                $length = $this->_decodeLength($key);
                $components['modulus'] = new KiboboCryptBigInteger($this->_string_shift($key, $length), 256);
                $this->_string_shift($key);
                $length = $this->_decodeLength($key);
                $components['publicExponent'] = new KiboboCryptBigInteger($this->_string_shift($key, $length), 256);
                $this->_string_shift($key);
                $length = $this->_decodeLength($key);
                $components['privateExponent'] = new KiboboCryptBigInteger($this->_string_shift($key, $length), 256);
                $this->_string_shift($key);
                $length = $this->_decodeLength($key);
                $components['primes'] = array(1 => new KiboboCryptBigInteger($this->_string_shift($key, $length), 256));
                $this->_string_shift($key);
                $length = $this->_decodeLength($key);
                $components['primes'][] = new KiboboCryptBigInteger($this->_string_shift($key, $length), 256);
                $this->_string_shift($key);
                $length = $this->_decodeLength($key);
                $components['exponents'] = array(1 => new KiboboCryptBigInteger($this->_string_shift($key, $length), 256));
                $this->_string_shift($key);
                $length = $this->_decodeLength($key);
                $components['exponents'][] = new KiboboCryptBigInteger($this->_string_shift($key, $length), 256);
                $this->_string_shift($key);
                $length = $this->_decodeLength($key);
                $components['coefficients'] = array(2 => new KiboboCryptBigInteger($this->_string_shift($key, $length), 256));

                if (!empty($key)) {
                    if (ord($this->_string_shift($key)) != self::ASN1_SEQUENCE) {
                        return false;
                    }
                    $this->_decodeLength($key);
                    while (!empty($key)) {
                        if (ord($this->_string_shift($key)) != self::ASN1_SEQUENCE) {
                            return false;
                        }
                        $this->_decodeLength($key);
                        $key = substr($key, 1);
                        $length = $this->_decodeLength($key);
                        $components['primes'][] = new KiboboCryptBigInteger($this->_string_shift($key, $length), 256);
                        $this->_string_shift($key);
                        $length = $this->_decodeLength($key);
                        $components['exponents'][] = new KiboboCryptBigInteger($this->_string_shift($key, $length), 256);
                        $this->_string_shift($key);
                        $length = $this->_decodeLength($key);
                        $components['coefficients'][] = new KiboboCryptBigInteger($this->_string_shift($key, $length), 256);
                    }
                }

                return $components;
            case self::PUBLIC_FORMAT_OPENSSH:
                $parts = explode(' ', $key, 3);

                $key = isset($parts[1]) ? base64_decode($parts[1]) : false;
                if ($key === false) {
                    return false;
                }

                $comment = isset($parts[2]) ? $parts[2] : false;

                $cleanup = substr($key, 0, 11) == "\0\0\0\7ssh-rsa";

                if (strlen($key) <= 4) {
                    return false;
                }
                extract(unpack('Nlength', $this->_string_shift($key, 4)));
                $publicExponent = new KiboboCryptBigInteger($this->_string_shift($key, $length), -256);
                if (strlen($key) <= 4) {
                    return false;
                }
                extract(unpack('Nlength', $this->_string_shift($key, 4)));
                $modulus = new KiboboCryptBigInteger($this->_string_shift($key, $length), -256);

                if ($cleanup && strlen($key)) {
                    if (strlen($key) <= 4) {
                        return false;
                    }
                    extract(unpack('Nlength', $this->_string_shift($key, 4)));
                    $realModulus = new KiboboCryptBigInteger($this->_string_shift($key, $length), -256);
                    return strlen($key) ? false : array(
                        'modulus' => $realModulus,
                        'publicExponent' => $modulus,
                        'comment' => $comment
                    );
                } else {
                    return strlen($key) ? false : array(
                        'modulus' => $modulus,
                        'publicExponent' => $publicExponent,
                        'comment' => $comment
                    );
                }
            // http://www.w3.org/TR/xmldsig-core/#sec-RSAKeyValue
            // http://en.wikipedia.org/wiki/XML_Signature
            case self::PRIVATE_FORMAT_XML:
            case self::PUBLIC_FORMAT_XML:
                if (!extension_loaded('xml')) {
                    return false;
                }

                $this->components = array();

                $xml = xml_parser_create('UTF-8');
                xml_set_object($xml, $this);
                xml_set_element_handler($xml, '_start_element_handler', '_stop_element_handler');
                xml_set_character_data_handler($xml, '_data_handler');
                // add <xml></xml> to account for "dangling" tags like <BitStrength>...</BitStrength> that are sometimes added
                if (!xml_parse($xml, '<xml>' . $key . '</xml>')) {
                    xml_parser_free($xml);
                    unset($xml);
                    return false;
                }

                xml_parser_free($xml);
                unset($xml);

                return isset($this->components['modulus']) && isset($this->components['publicExponent']) ? $this->components : false;
            // see PuTTY's SSHPUBK.C and https://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixC.html
            case self::PRIVATE_FORMAT_PUTTY:
                $components = array();
                $key = preg_split('#\r\n|\r|\n#', $key);
                if ($this->_string_shift($key[0], strlen('PuTTY-User-Key-File-')) != 'PuTTY-User-Key-File-') {
                    return false;
                }
                $version = (int) $this->_string_shift($key[0], 3); // should be either "2: " or "3: 0" prior to int casting
                if ($version != 2 && $version != 3) {
                    return false;
                }
                $type = rtrim($key[0]);
                if ($type != 'ssh-rsa') {
                    return false;
                }
                $encryption = trim(preg_replace('#Encryption: (.+)#', '$1', $key[1]));
                $comment = trim(preg_replace('#Comment: (.+)#', '$1', $key[2]));

                $publicLength = trim(preg_replace('#Public-Lines: (\d+)#', '$1', $key[3]));
                $public = base64_decode(implode('', array_map('trim', array_slice($key, 4, $publicLength))));
                $public = substr($public, 11);
                extract(unpack('Nlength', $this->_string_shift($public, 4)));
                $components['publicExponent'] = new KiboboCryptBigInteger($this->_string_shift($public, $length), -256);
                extract(unpack('Nlength', $this->_string_shift($public, 4)));
                $components['modulus'] = new KiboboCryptBigInteger($this->_string_shift($public, $length), -256);

                $offset = $publicLength + 4;
                switch ($encryption) {
                    case 'aes256-cbc':
                        $crypto = new AES();
                        switch ($version) {
                            case 3:
                                if (!function_exists('sodium_crypto_pwhash')) {
                                    return false;
                                }
                                $flavour = trim(preg_replace('#Key-Derivation: (.*)#', '$1', $key[$offset++]));
                                switch ($flavour) {
                                    case 'Argon2i':
                                        $flavour = SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13;
                                        break;
                                    case 'Argon2id':
                                        $flavour = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13;
                                        break;
                                    default:
                                        return false;
                                }
                                $memory = trim(preg_replace('#Argon2-Memory: (\d+)#', '$1', $key[$offset++]));
                                $passes = trim(preg_replace('#Argon2-Passes: (\d+)#', '$1', $key[$offset++]));
                                $parallelism = trim(preg_replace('#Argon2-Parallelism: (\d+)#', '$1', $key[$offset++]));
                                $salt = pack('H*', trim(preg_replace('#Argon2-Salt: ([0-9a-f]+)#', '$1', $key[$offset++])));

                                $length = 80; // keylen + ivlen + mac_keylen
                                $temp = sodium_crypto_pwhash($length, $this->password, $salt, $passes, $memory << 10, $flavour);

                                $symkey = substr($temp, 0, 32);
                                $symiv = substr($temp, 32, 16);
                                break;
                            case 2:
                                $symkey = '';
                                $sequence = 0;
                                while (strlen($symkey) < 32) {
                                    $temp = pack('Na*', $sequence++, $this->password);
                                    $symkey.= pack('H*', sha1($temp));
                                }
                                $symkey = substr($symkey, 0, 32);
                                $symiv = str_repeat("\0", 16);
                        }
                }

                $privateLength = trim(preg_replace('#Private-Lines: (\d+)#', '$1', $key[$offset++]));
                $private = base64_decode(implode('', array_map('trim', array_slice($key, $offset, $privateLength))));

                if ($encryption != 'none') {
                    $crypto->setKey($symkey);
                    $crypto->setIV($symiv);
                    $crypto->disablePadding();
                    $private = $crypto->decrypt($private);
                    if ($private === false) {
                        return false;
                    }
                }

                extract(unpack('Nlength', $this->_string_shift($private, 4)));
                if (strlen($private) < $length) {
                    return false;
                }
                $components['privateExponent'] = new KiboboCryptBigInteger($this->_string_shift($private, $length), -256);
                extract(unpack('Nlength', $this->_string_shift($private, 4)));
                if (strlen($private) < $length) {
                    return false;
                }
                $components['primes'] = array(1 => new KiboboCryptBigInteger($this->_string_shift($private, $length), -256));
                extract(unpack('Nlength', $this->_string_shift($private, 4)));
                if (strlen($private) < $length) {
                    return false;
                }
                $components['primes'][] = new KiboboCryptBigInteger($this->_string_shift($private, $length), -256);

                $temp = $components['primes'][1]->subtract($this->one);
                $components['exponents'] = array(1 => $components['publicExponent']->modInverse($temp));
                $temp = $components['primes'][2]->subtract($this->one);
                $components['exponents'][] = $components['publicExponent']->modInverse($temp);

                extract(unpack('Nlength', $this->_string_shift($private, 4)));
                if (strlen($private) < $length) {
                    return false;
                }
                $components['coefficients'] = array(2 => new BKiboboCryptigInteger($this->_string_shift($private, $length), -256));

                return $components;
            case self::PRIVATE_FORMAT_OPENSSH:
                $components = array();
                $decoded = $this->_extractBER($key);
                $magic = $this->_string_shift($decoded, 15);
                if ($magic !== "openssh-key-v1\0") {
                    return false;
                }
                extract(unpack('Nlength', $this->_string_shift($decoded, 4)));
                if (strlen($decoded) < $length) {
                    return false;
                }
                $ciphername = $this->_string_shift($decoded, $length);
                extract(unpack('Nlength', $this->_string_shift($decoded, 4)));
                if (strlen($decoded) < $length) {
                    return false;
                }
                $kdfname = $this->_string_shift($decoded, $length);
                extract(unpack('Nlength', $this->_string_shift($decoded, 4)));
                if (strlen($decoded) < $length) {
                    return false;
                }
                $kdfoptions = $this->_string_shift($decoded, $length);
                extract(unpack('Nnumkeys', $this->_string_shift($decoded, 4)));
                if ($numkeys != 1 || ($ciphername != 'none' && $kdfname != 'bcrypt')) {
                    return false;
                }
                switch ($ciphername) {
                    case 'none':
                        break;
                    case 'aes256-ctr':
                        extract(unpack('Nlength', $this->_string_shift($kdfoptions, 4)));
                        if (strlen($kdfoptions) < $length) {
                            return false;
                        }
                        $salt = $this->_string_shift($kdfoptions, $length);
                        extract(unpack('Nrounds', $this->_string_shift($kdfoptions, 4)));
                        $crypto = new KiboboCryptAES(KiboboCryptAES::MODE_CTR);
                        $crypto->disablePadding();
                        if (!$crypto->setPassword($this->password, 'bcrypt', $salt, $rounds, 32)) {
                            return false;
                        }
                        break;
                    default:
                        return false;
                }
                extract(unpack('Nlength', $this->_string_shift($decoded, 4)));
                if (strlen($decoded) < $length) {
                    return false;
                }
                $publicKey = $this->_string_shift($decoded, $length);
                extract(unpack('Nlength', $this->_string_shift($decoded, 4)));
                if (strlen($decoded) < $length) {
                    return false;
                }

                if ($this->_string_shift($publicKey, 11) !== "\0\0\0\7ssh-rsa") {
                    return false;
                }

                $paddedKey = $this->_string_shift($decoded, $length);
                if (isset($crypto)) {
                    $paddedKey = $crypto->decrypt($paddedKey);
                }

                $checkint1 = $this->_string_shift($paddedKey, 4);
                $checkint2 = $this->_string_shift($paddedKey, 4);
                if (strlen($checkint1) != 4 || $checkint1 !== $checkint2) {
                    return false;
                }

                if ($this->_string_shift($paddedKey, 11) !== "\0\0\0\7ssh-rsa") {
                    return false;
                }

                $values = array(
                    &$components['modulus'],
                    &$components['publicExponent'],
                    &$components['privateExponent'],
                    &$components['coefficients'][2],
                    &$components['primes'][1],
                    &$components['primes'][2]
                );

                foreach ($values as &$value) {
                    extract(unpack('Nlength', $this->_string_shift($paddedKey, 4)));
                    if (strlen($paddedKey) < $length) {
                        return false;
                    }
                    $value = new KiboboCryptBigInteger($this->_string_shift($paddedKey, $length), -256);
                }

                extract(unpack('Nlength', $this->_string_shift($paddedKey, 4)));
                if (strlen($paddedKey) < $length) {
                    return false;
                }
                $components['comment'] = $this->_string_shift($decoded, $length);

                $temp = $components['primes'][1]->subtract($this->one);
                $components['exponents'] = array(1 => $components['publicExponent']->modInverse($temp));
                $temp = $components['primes'][2]->subtract($this->one);
                $components['exponents'][] = $components['publicExponent']->modInverse($temp);

                return $components;
        }

        return false;
    }

    /**
     * Returns the key size
     *
     * More specifically, this returns the size of the modulo in bits.
     *
     * @access public
     * @return int
     */
    function getSize()
    {
        return !isset($this->modulus) ? 0 : strlen($this->modulus->toBits());
    }

    /**
     * Start Element Handler
     *
     * Called by xml_set_element_handler()
     *
     * @access private
     * @param resource $parser
     * @param string $name
     * @param array $attribs
     */
    function _start_element_handler($parser, $name, $attribs)
    {
        //$name = strtoupper($name);
        switch ($name) {
            case 'MODULUS':
                $this->current = &$this->components['modulus'];
                break;
            case 'EXPONENT':
                $this->current = &$this->components['publicExponent'];
                break;
            case 'P':
                $this->current = &$this->components['primes'][1];
                break;
            case 'Q':
                $this->current = &$this->components['primes'][2];
                break;
            case 'DP':
                $this->current = &$this->components['exponents'][1];
                break;
            case 'DQ':
                $this->current = &$this->components['exponents'][2];
                break;
            case 'INVERSEQ':
                $this->current = &$this->components['coefficients'][2];
                break;
            case 'D':
                $this->current = &$this->components['privateExponent'];
        }
        $this->current = '';
    }

    /**
     * Stop Element Handler
     *
     * Called by xml_set_element_handler()
     *
     * @access private
     * @param resource $parser
     * @param string $name
     */
    function _stop_element_handler($parser, $name)
    {
        if (isset($this->current)) {
            $this->current = new KiboboCryptBigInteger(base64_decode($this->current), 256);
            unset($this->current);
        }
    }

    /**
     * Data Handler
     *
     * Called by xml_set_character_data_handler()
     *
     * @access private
     * @param resource $parser
     * @param string $data
     */
    function _data_handler($parser, $data)
    {
        if (!isset($this->current) || is_object($this->current)) {
            return;
        }
        $this->current.= trim($data);
    }

    /**
     * Loads a public or private key
     *
     * Returns true on success and false on failure (ie. an incorrect password was provided or the key was malformed)
     *
     * @access public
     * @param string|RSA|array $key
     * @param bool|int $type optional
     * @return bool
     */
    function loadKey($key, $type = false)
    {
        if ($key instanceof RSA) {
            $this->privateKeyFormat = $key->privateKeyFormat;
            $this->publicKeyFormat = $key->publicKeyFormat;
            $this->k = $key->k;
            $this->hLen = $key->hLen;
            $this->sLen = $key->sLen;
            $this->mgfHLen = $key->mgfHLen;
            $this->encryptionMode = $key->encryptionMode;
            $this->signatureMode = $key->signatureMode;
            $this->password = $key->password;
            $this->configFile = $key->configFile;
            $this->comment = $key->comment;

            if (is_object($key->hash)) {
                $this->hash = new KiboboCryptHash($key->hash->getHash());
            }
            if (is_object($key->mgfHash)) {
                $this->mgfHash = new KiboboCryptHash($key->mgfHash->getHash());
            }

            if (is_object($key->modulus)) {
                $this->modulus = $key->modulus->copy();
            }
            if (is_object($key->exponent)) {
                $this->exponent = $key->exponent->copy();
            }
            if (is_object($key->publicExponent)) {
                $this->publicExponent = $key->publicExponent->copy();
            }

            $this->primes = array();
            $this->exponents = array();
            $this->coefficients = array();

            foreach ($this->primes as $prime) {
                $this->primes[] = $prime->copy();
            }
            foreach ($this->exponents as $exponent) {
                $this->exponents[] = $exponent->copy();
            }
            foreach ($this->coefficients as $coefficient) {
                $this->coefficients[] = $coefficient->copy();
            }

            return true;
        }

        if ($type === false) {
            $types = array(
                self::PUBLIC_FORMAT_RAW,
                self::PRIVATE_FORMAT_PKCS1,
                self::PRIVATE_FORMAT_XML,
                self::PRIVATE_FORMAT_PUTTY,
                self::PUBLIC_FORMAT_OPENSSH,
                self::PRIVATE_FORMAT_OPENSSH
            );
            foreach ($types as $type) {
                $components = $this->_parseKey($key, $type);
                if ($components !== false) {
                    break;
                }
            }
        } else {
            $components = $this->_parseKey($key, $type);
        }

        if ($components === false) {
            $this->comment = null;
            $this->modulus = null;
            $this->k = null;
            $this->exponent = null;
            $this->primes = null;
            $this->exponents = null;
            $this->coefficients = null;
            $this->publicExponent = null;

            return false;
        }

        if (isset($components['comment']) && $components['comment'] !== false) {
            $this->comment = $components['comment'];
        }
        $this->modulus = $components['modulus'];
        $this->k = strlen($this->modulus->toBytes());
        $this->exponent = isset($components['privateExponent']) ? $components['privateExponent'] : $components['publicExponent'];
        if (isset($components['primes'])) {
            $this->primes = $components['primes'];
            $this->exponents = $components['exponents'];
            $this->coefficients = $components['coefficients'];
            $this->publicExponent = $components['publicExponent'];
        } else {
            $this->primes = array();
            $this->exponents = array();
            $this->coefficients = array();
            $this->publicExponent = false;
        }

        switch ($type) {
            case self::PUBLIC_FORMAT_OPENSSH:
            case self::PUBLIC_FORMAT_RAW:
                $this->setPublicKey();
                break;
            case self::PRIVATE_FORMAT_PKCS1:
                switch (true) {
                    case strpos($key, '-BEGIN PUBLIC KEY-') !== false:
                    case strpos($key, '-BEGIN RSA PUBLIC KEY-') !== false:
                        $this->setPublicKey();
                }
        }

        return true;
    }

    /**
     * Sets the password
     *
     * Private keys can be encrypted with a password.  To unset the password, pass in the empty string or false.
     * Or rather, pass in $password such that empty($password) && !is_string($password) is true.
     *
     * @see self::createKey()
     * @see self::loadKey()
     * @access public
     * @param string $password
     */
    function setPassword($password = false)
    {
        $this->password = $password;
    }

    /**
     * Defines the public key
     *
     * Some private key formats define the public exponent and some don't.  Those that don't define it are problematic when
     * used in certain contexts.  For example, in SSH-2, RSA authentication works by sending the public key along with a
     * message signed by the private key to the server.  The SSH-2 server looks the public key up in an index of public keys
     * and if it's present then proceeds to verify the signature.  Problem is, if your private key doesn't include the public
     * exponent this won't work unless you manually add the public exponent. phpseclib tries to guess if the key being used
     * is the public key but in the event that it guesses incorrectly you might still want to explicitly set the key as being
     * public.
     *
     * Do note that when a new key is loaded the index will be cleared.
     *
     * Returns true on success, false on failure
     *
     * @see self::getPublicKey()
     * @access public
     * @param string $key optional
     * @param int $type optional
     * @return bool
     */
    function setPublicKey($key = false, $type = false)
    {
        // if a public key has already been loaded return false
        if (!empty($this->publicExponent)) {
            return false;
        }

        if ($key === false && !empty($this->modulus)) {
            $this->publicExponent = $this->exponent;
            return true;
        }

        if ($type === false) {
            $types = array(
                self::PUBLIC_FORMAT_RAW,
                self::PUBLIC_FORMAT_PKCS1,
                self::PUBLIC_FORMAT_XML,
                self::PUBLIC_FORMAT_OPENSSH
            );
            foreach ($types as $type) {
                $components = $this->_parseKey($key, $type);
                if ($components !== false) {
                    break;
                }
            }
        } else {
            $components = $this->_parseKey($key, $type);
        }

        if ($components === false) {
            return false;
        }

        if (empty($this->modulus) || !$this->modulus->equals($components['modulus'])) {
            $this->modulus = $components['modulus'];
            $this->exponent = $this->publicExponent = $components['publicExponent'];
            return true;
        }

        $this->publicExponent = $components['publicExponent'];

        return true;
    }

    /**
     * Defines the private key
     *
     * If phpseclib guessed a private key was a public key and loaded it as such it might be desirable to force
     * phpseclib to treat the key as a private key. This function will do that.
     *
     * Do note that when a new key is loaded the index will be cleared.
     *
     * Returns true on success, false on failure
     *
     * @see self::getPublicKey()
     * @access public
     * @param string $key optional
     * @param int $type optional
     * @return bool
     */
    function setPrivateKey($key = false, $type = false)
    {
        if ($key === false && !empty($this->publicExponent)) {
            $this->publicExponent = false;
            return true;
        }

        $rsa = new KiboboCryptRSA();
        if (!$rsa->loadKey($key, $type)) {
            return false;
        }
        $rsa->publicExponent = false;

        // don't overwrite the old key if the new key is invalid
        $this->loadKey($rsa);
        return true;
    }

    /**
     * Returns the public key
     *
     * The public key is only returned under two circumstances - if the private key had the public key embedded within it
     * or if the public key was set via setPublicKey().  If the currently loaded key is supposed to be the public key this
     * function won't return it since this library, for the most part, doesn't distinguish between public and private keys.
     *
     * @see self::getPublicKey()
     * @access public
     * @param int $type optional
     */
    function getPublicKey($type = self::PUBLIC_FORMAT_PKCS8)
    {
        if (empty($this->modulus) || empty($this->publicExponent)) {
            return false;
        }

        $oldFormat = $this->publicKeyFormat;
        $this->publicKeyFormat = $type;
        $temp = $this->_convertPublicKey($this->modulus, $this->publicExponent);
        $this->publicKeyFormat = $oldFormat;
        return $temp;
    }

    /**
     * Returns the public key's fingerprint
     *
     * The public key's fingerprint is returned, which is equivalent to running `ssh-keygen -lf rsa.pub`. If there is
     * no public key currently loaded, false is returned.
     * Example output (md5): "c1:b1:30:29:d7:b8:de:6c:97:77:10:d7:46:41:63:87" (as specified by RFC 4716)
     *
     * @access public
     * @param string $algorithm The hashing algorithm to be used. Valid options are 'md5' and 'sha256'. False is returned
     * for invalid values.
     * @return mixed
     */
    function getPublicKeyFingerprint($algorithm = 'md5')
    {
        if (empty($this->modulus) || empty($this->publicExponent)) {
            return false;
        }

        $modulus = $this->modulus->toBytes(true);
        $publicExponent = $this->publicExponent->toBytes(true);

        $RSAPublicKey = pack('Na*Na*Na*', strlen('ssh-rsa'), 'ssh-rsa', strlen($publicExponent), $publicExponent, strlen($modulus), $modulus);

        switch ($algorithm) {
            case 'sha256':
                $hash = new KiboboCryptHash('sha256');
                $base = base64_encode($hash->hash($RSAPublicKey));
                return substr($base, 0, strlen($base) - 1);
            case 'md5':
                return substr(chunk_split(md5($RSAPublicKey), 2, ':'), 0, -1);
            default:
                return false;
        }
    }

    /**
     * Returns the private key
     *
     * The private key is only returned if the currently loaded key contains the constituent prime numbers.
     *
     * @see self::getPublicKey()
     * @access public
     * @param int $type optional
     * @return mixed
     */
    function getPrivateKey($type = self::PUBLIC_FORMAT_PKCS1)
    {
        if (empty($this->primes)) {
            return false;
        }

        $oldFormat = $this->privateKeyFormat;
        $this->privateKeyFormat = $type;
        $temp = $this->_convertPrivateKey($this->modulus, $this->publicExponent, $this->exponent, $this->primes, $this->exponents, $this->coefficients);
        $this->privateKeyFormat = $oldFormat;
        return $temp;
    }

    /**
     * Returns a minimalistic private key
     *
     * Returns the private key without the prime number constituants.  Structurally identical to a public key that
     * hasn't been set as the public key
     *
     * @see self::getPrivateKey()
     * @access private
     * @param int $mode optional
     */
    function _getPrivatePublicKey($mode = self::PUBLIC_FORMAT_PKCS8)
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            return false;
        }

        $oldFormat = $this->publicKeyFormat;
        $this->publicKeyFormat = $mode;
        $temp = $this->_convertPublicKey($this->modulus, $this->exponent);
        $this->publicKeyFormat = $oldFormat;
        return $temp;
    }

    /**
     *  __toString() magic method
     *
     * @access public
     * @return string
     */
    function __toString()
    {
        $key = $this->getPrivateKey($this->privateKeyFormat);
        if ($key !== false) {
            return $key;
        }
        $key = $this->_getPrivatePublicKey($this->publicKeyFormat);
        return $key !== false ? $key : '';
    }

    /**
     *  __clone() magic method
     *
     * @access public
     * @return Crypt_RSA
     */
    function __clone()
    {
        $key = new KiboboCryptRSA();
        $key->loadKey($this);
        return $key;
    }

    /**
     * Generates the smallest and largest numbers requiring $bits bits
     *
     * @access private
     * @param int $bits
     * @return array
     */
    function _generateMinMax($bits)
    {
        $bytes = $bits >> 3;
        $min = str_repeat(chr(0), $bytes);
        $max = str_repeat(chr(0xFF), $bytes);
        $msb = $bits & 7;
        if ($msb) {
            $min = chr(1 << ($msb - 1)) . $min;
            $max = chr((1 << $msb) - 1) . $max;
        } else {
            $min[0] = chr(0x80);
        }

        return array(
            'min' => new KiboboCryptBigInteger($min, 256),
            'max' => new KiboboCryptBigInteger($max, 256)
        );
    }

    /**
     * DER-decode the length
     *
     * DER supports lengths up to (2**8)**127, however, we'll only support lengths up to (2**8)**4.  See
     * {@link http://itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#p=13 X.690 paragraph 8.1.3} for more information.
     *
     * @access private
     * @param string $string
     * @return int
     */
    function _decodeLength(&$string)
    {
        $length = ord($this->_string_shift($string));
        if ($length & 0x80) { // definite length, long form
            $length&= 0x7F;
            $temp = $this->_string_shift($string, $length);
            list(, $length) = unpack('N', substr(str_pad($temp, 4, chr(0), STR_PAD_LEFT), -4));
        }
        return $length;
    }

    /**
     * DER-encode the length
     *
     * DER supports lengths up to (2**8)**127, however, we'll only support lengths up to (2**8)**4.  See
     * {@link http://itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#p=13 X.690 paragraph 8.1.3} for more information.
     *
     * @access private
     * @param int $length
     * @return string
     */
    function _encodeLength($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }

    /**
     * String Shift
     *
     * Inspired by array_shift
     *
     * @param string $string
     * @param int $index
     * @return string
     * @access private
     */
    function _string_shift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }

    /**
     * Determines the private key format
     *
     * @see self::createKey()
     * @access public
     * @param int $format
     */
    function setPrivateKeyFormat($format)
    {
        $this->privateKeyFormat = $format;
    }

    /**
     * Determines the public key format
     *
     * @see self::createKey()
     * @access public
     * @param int $format
     */
    function setPublicKeyFormat($format)
    {
        $this->publicKeyFormat = $format;
    }

    /**
     * Determines which hashing function should be used
     *
     * Used with signature production / verification and (if the encryption mode is self::ENCRYPTION_OAEP) encryption and
     * decryption.  If $hash isn't supported, sha1 is used.
     *
     * @access public
     * @param string $hash
     */
    function setHash($hash)
    {
        // \phpseclib\Crypt\Hash supports algorithms that PKCS#1 doesn't support.  md5-96 and sha1-96, for example.
        switch ($hash) {
            case 'md2':
            case 'md5':
            case 'sha1':
            case 'sha256':
            case 'sha384':
            case 'sha512':
                $this->hash = new KiboboCryptHash($hash);
                $this->hashName = $hash;
                break;
            default:
                $this->hash = new KiboboCryptHash('sha1');
                $this->hashName = 'sha1';
        }
        $this->hLen = $this->hash->getLength();
    }

    /**
     * Determines which hashing function should be used for the mask generation function
     *
     * The mask generation function is used by self::ENCRYPTION_OAEP and self::SIGNATURE_PSS and although it's
     * best if Hash and MGFHash are set to the same thing this is not a requirement.
     *
     * @access public
     * @param string $hash
     */
    function setMGFHash($hash)
    {
        // \phpseclib\Crypt\Hash supports algorithms that PKCS#1 doesn't support.  md5-96 and sha1-96, for example.
        switch ($hash) {
            case 'md2':
            case 'md5':
            case 'sha1':
            case 'sha256':
            case 'sha384':
            case 'sha512':
                $this->mgfHash = new KiboboCryptHash($hash);
                break;
            default:
                $this->mgfHash = new KiboboCryptHash('sha1');
        }
        $this->mgfHLen = $this->mgfHash->getLength();
    }

    /**
     * Determines the salt length
     *
     * To quote from {@link http://tools.ietf.org/html/rfc3447#page-38 RFC3447#page-38}:
     *
     *    Typical salt lengths in octets are hLen (the length of the output
     *    of the hash function Hash) and 0.
     *
     * @access public
     * @param int $sLen
     */
    function setSaltLength($sLen)
    {
        $this->sLen = $sLen;
    }

    /**
     * Integer-to-Octet-String primitive
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-4.1 RFC3447#section-4.1}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $x
     * @param int $xLen
     * @return string
     */
    function _i2osp($x, $xLen)
    {
        $x = $x->toBytes();
        if (strlen($x) > $xLen) {
            user_error('Integer too large');
            return false;
        }
        return str_pad($x, $xLen, chr(0), STR_PAD_LEFT);
    }

    /**
     * Octet-String-to-Integer primitive
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-4.2 RFC3447#section-4.2}.
     *
     * @access private
     * @param int|string|resource $x
     * @return \phpseclib\Math\BigInteger
     */
    function _os2ip($x)
    {
        return new KiboboCryptBigInteger($x, 256);
    }

    /**
     * Exponentiate with or without Chinese Remainder Theorem
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.1 RFC3447#section-5.1.2}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $x
     * @return \phpseclib\Math\BigInteger
     */
    function _exponentiate($x)
    {
        switch (true) {
            case empty($this->primes):
            case $this->primes[1]->equals($this->zero):
            case empty($this->coefficients):
            case $this->coefficients[2]->equals($this->zero):
            case empty($this->exponents):
            case $this->exponents[1]->equals($this->zero):
                return $x->modPow($this->exponent, $this->modulus);
        }

        $num_primes = count($this->primes);

        if (defined('CRYPT_RSA_DISABLE_BLINDING')) {
            $m_i = array(
                1 => $x->modPow($this->exponents[1], $this->primes[1]),
                2 => $x->modPow($this->exponents[2], $this->primes[2])
            );
            $h = $m_i[1]->subtract($m_i[2]);
            $h = $h->multiply($this->coefficients[2]);
            list(, $h) = $h->divide($this->primes[1]);
            $m = $m_i[2]->add($h->multiply($this->primes[2]));

            $r = $this->primes[1];
            for ($i = 3; $i <= $num_primes; $i++) {
                $m_i = $x->modPow($this->exponents[$i], $this->primes[$i]);

                $r = $r->multiply($this->primes[$i - 1]);

                $h = $m_i->subtract($m);
                $h = $h->multiply($this->coefficients[$i]);
                list(, $h) = $h->divide($this->primes[$i]);

                $m = $m->add($r->multiply($h));
            }
        } else {
            $smallest = $this->primes[1];
            for ($i = 2; $i <= $num_primes; $i++) {
                if ($smallest->compare($this->primes[$i]) > 0) {
                    $smallest = $this->primes[$i];
                }
            }

            $one = new KiboboCryptBigInteger(1);

            $r = $one->random($one, $smallest->subtract($one));

            $m_i = array(
                1 => $this->_blind($x, $r, 1),
                2 => $this->_blind($x, $r, 2)
            );
            $h = $m_i[1]->subtract($m_i[2]);
            $h = $h->multiply($this->coefficients[2]);
            list(, $h) = $h->divide($this->primes[1]);
            $m = $m_i[2]->add($h->multiply($this->primes[2]));

            $r = $this->primes[1];
            for ($i = 3; $i <= $num_primes; $i++) {
                $m_i = $this->_blind($x, $r, $i);

                $r = $r->multiply($this->primes[$i - 1]);

                $h = $m_i->subtract($m);
                $h = $h->multiply($this->coefficients[$i]);
                list(, $h) = $h->divide($this->primes[$i]);

                $m = $m->add($r->multiply($h));
            }
        }

        return $m;
    }

    /**
     * Performs RSA Blinding
     *
     * Protects against timing attacks by employing RSA Blinding.
     * Returns $x->modPow($this->exponents[$i], $this->primes[$i])
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $x
     * @param \phpseclib\Math\BigInteger $r
     * @param int $i
     * @return \phpseclib\Math\BigInteger
     */
    function _blind($x, $r, $i)
    {
        $x = $x->multiply($r->modPow($this->publicExponent, $this->primes[$i]));
        $x = $x->modPow($this->exponents[$i], $this->primes[$i]);

        $r = $r->modInverse($this->primes[$i]);
        $x = $x->multiply($r);
        list(, $x) = $x->divide($this->primes[$i]);

        return $x;
    }

    /**
     * Performs blinded RSA equality testing
     *
     * Protects against a particular type of timing attack described.
     *
     * See {@link http://codahale.com/a-lesson-in-timing-attacks/ A Lesson In Timing Attacks (or, Don't use MessageDigest.isEquals)}
     *
     * Thanks for the heads up singpolyma!
     *
     * @access private
     * @param string $x
     * @param string $y
     * @return bool
     */
    function _equals($x, $y)
    {
        if (function_exists('hash_equals')) {
            return hash_equals($x, $y);
        }

        if (strlen($x) != strlen($y)) {
            return false;
        }

        $result = "\0";
        $x^= $y;
        for ($i = 0; $i < strlen($x); $i++) {
            $result|= $x[$i];
        }

        return $result === "\0";
    }

    /**
     * RSAEP
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.1 RFC3447#section-5.1.1}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $m
     * @return \phpseclib\Math\BigInteger
     */
    function _rsaep($m)
    {
        if ($m->compare($this->zero) < 0 || $m->compare($this->modulus) > 0) {
            user_error('Message representative out of range');
            return false;
        }
        return $this->_exponentiate($m);
    }

    /**
     * RSADP
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.2 RFC3447#section-5.1.2}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $c
     * @return \phpseclib\Math\BigInteger
     */
    function _rsadp($c)
    {
        if ($c->compare($this->zero) < 0 || $c->compare($this->modulus) > 0) {
            user_error('Ciphertext representative out of range');
            return false;
        }
        return $this->_exponentiate($c);
    }

    /**
     * RSASP1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.2.1 RFC3447#section-5.2.1}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $m
     * @return \phpseclib\Math\BigInteger
     */
    function _rsasp1($m)
    {
        if ($m->compare($this->zero) < 0 || $m->compare($this->modulus) > 0) {
            user_error('Message representative out of range');
            return false;
        }
        return $this->_exponentiate($m);
    }

    /**
     * RSAVP1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.2.2 RFC3447#section-5.2.2}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $s
     * @return \phpseclib\Math\BigInteger
     */
    function _rsavp1($s)
    {
        if ($s->compare($this->zero) < 0 || $s->compare($this->modulus) > 0) {
            user_error('Signature representative out of range');
            return false;
        }
        return $this->_exponentiate($s);
    }

    /**
     * MGF1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#appendix-B.2.1 RFC3447#appendix-B.2.1}.
     *
     * @access private
     * @param string $mgfSeed
     * @param int $maskLen
     * @return string
     */
    function _mgf1($mgfSeed, $maskLen)
    {
        // if $maskLen would yield strings larger than 4GB, PKCS#1 suggests a "Mask too long" error be output.

        $t = '';
        $count = ceil($maskLen / $this->mgfHLen);
        for ($i = 0; $i < $count; $i++) {
            $c = pack('N', $i);
            $t.= $this->mgfHash->hash($mgfSeed . $c);
        }

        return substr($t, 0, $maskLen);
    }

    /**
     * RSAES-OAEP-ENCRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.1.1 RFC3447#section-7.1.1} and
     * {http://en.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding OAES}.
     *
     * @access private
     * @param string $m
     * @param string $l
     * @return string
     */
    function _rsaes_oaep_encrypt($m, $l = '')
    {
        $mLen = strlen($m);

        // Length checking

        // if $l is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        if ($mLen > $this->k - 2 * $this->hLen - 2) {
            user_error('Message too long');
            return false;
        }

        // EME-OAEP encoding

        $lHash = $this->hash->hash($l);
        $ps = str_repeat(chr(0), $this->k - $mLen - 2 * $this->hLen - 2);
        $db = $lHash . $ps . chr(1) . $m;
        $seed = Random::string($this->hLen);
        $dbMask = $this->_mgf1($seed, $this->k - $this->hLen - 1);
        $maskedDB = $db ^ $dbMask;
        $seedMask = $this->_mgf1($maskedDB, $this->hLen);
        $maskedSeed = $seed ^ $seedMask;
        $em = chr(0) . $maskedSeed . $maskedDB;

        // RSA encryption

        $m = $this->_os2ip($em);
        $c = $this->_rsaep($m);
        $c = $this->_i2osp($c, $this->k);

        // Output the ciphertext C

        return $c;
    }

    /**
     * RSAES-OAEP-DECRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.1.2 RFC3447#section-7.1.2}.  The fact that the error
     * messages aren't distinguishable from one another hinders debugging, but, to quote from RFC3447#section-7.1.2:
     *
     *    Note.  Care must be taken to ensure that an opponent cannot
     *    distinguish the different error conditions in Step 3.g, whether by
     *    error message or timing, or, more generally, learn partial
     *    information about the encoded message EM.  Otherwise an opponent may
     *    be able to obtain useful information about the decryption of the
     *    ciphertext C, leading to a chosen-ciphertext attack such as the one
     *    observed by Manger [36].
     *
     * As for $l...  to quote from {@link http://tools.ietf.org/html/rfc3447#page-17 RFC3447#page-17}:
     *
     *    Both the encryption and the decryption operations of RSAES-OAEP take
     *    the value of a label L as input.  In this version of PKCS #1, L is
     *    the empty string; other uses of the label are outside the scope of
     *    this document.
     *
     * @access private
     * @param string $c
     * @param string $l
     * @return string
     */
    function _rsaes_oaep_decrypt($c, $l = '')
    {
        // Length checking

        // if $l is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        if (strlen($c) != $this->k || $this->k < 2 * $this->hLen + 2) {
            user_error('Decryption error');
            return false;
        }

        // RSA decryption

        $c = $this->_os2ip($c);
        $m = $this->_rsadp($c);
        if ($m === false) {
            user_error('Decryption error');
            return false;
        }
        $em = $this->_i2osp($m, $this->k);

        // EME-OAEP decoding

        $lHash = $this->hash->hash($l);
        $y = ord($em[0]);
        $maskedSeed = substr($em, 1, $this->hLen);
        $maskedDB = substr($em, $this->hLen + 1);
        $seedMask = $this->_mgf1($maskedDB, $this->hLen);
        $seed = $maskedSeed ^ $seedMask;
        $dbMask = $this->_mgf1($seed, $this->k - $this->hLen - 1);
        $db = $maskedDB ^ $dbMask;
        $lHash2 = substr($db, 0, $this->hLen);
        $m = substr($db, $this->hLen);
        $hashesMatch = $this->_equals($lHash, $lHash2);
        $leadingZeros = 1;
        $patternMatch = 0;
        $offset = 0;
        for ($i = 0; $i < strlen($m); $i++) {
            $patternMatch|= $leadingZeros & ($m[$i] === "\1");
            $leadingZeros&= $m[$i] === "\0";
            $offset+= $patternMatch ? 0 : 1;
        }

        // we do | instead of || to avoid https://en.wikipedia.org/wiki/Short-circuit_evaluation
        // to protect against timing attacks
        if (!$hashesMatch | !$patternMatch) {
            user_error('Decryption error');
            return false;
        }

        // Output the message M

        return substr($m, $offset + 1);
    }

    /**
     * Raw Encryption / Decryption
     *
     * Doesn't use padding and is not recommended.
     *
     * @access private
     * @param string $m
     * @return string
     */
    function _raw_encrypt($m)
    {
        $temp = $this->_os2ip($m);
        $temp = $this->_rsaep($temp);
        return  $this->_i2osp($temp, $this->k);
    }

    /**
     * RSAES-PKCS1-V1_5-ENCRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.2.1 RFC3447#section-7.2.1}.
     *
     * @access private
     * @param string $m
     * @return string
     */
    function _rsaes_pkcs1_v1_5_encrypt($m)
    {
        $mLen = strlen($m);

        // Length checking

        if ($mLen > $this->k - 11) {
            user_error('Message too long');
            return false;
        }

        // EME-PKCS1-v1_5 encoding

        $psLen = $this->k - $mLen - 3;
        $ps = '';
        while (strlen($ps) != $psLen) {
            $temp = Random::string($psLen - strlen($ps));
            $temp = str_replace("\x00", '', $temp);
            $ps.= $temp;
        }
        $type = 2;
        // see the comments of _rsaes_pkcs1_v1_5_decrypt() to understand why this is being done
        if (defined('CRYPT_RSA_PKCS15_COMPAT') && (!isset($this->publicExponent) || $this->exponent !== $this->publicExponent)) {
            $type = 1;
            // "The padding string PS shall consist of k-3-||D|| octets. ... for block type 01, they shall have value FF"
            $ps = str_repeat("\xFF", $psLen);
        }
        $em = chr(0) . chr($type) . $ps . chr(0) . $m;

        // RSA encryption
        $m = $this->_os2ip($em);
        $c = $this->_rsaep($m);
        $c = $this->_i2osp($c, $this->k);

        // Output the ciphertext C

        return $c;
    }

    /**
     * RSAES-PKCS1-V1_5-DECRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.2.2 RFC3447#section-7.2.2}.
     *
     * For compatibility purposes, this function departs slightly from the description given in RFC3447.
     * The reason being that RFC2313#section-8.1 (PKCS#1 v1.5) states that ciphertext's encrypted by the
     * private key should have the second byte set to either 0 or 1 and that ciphertext's encrypted by the
     * public key should have the second byte set to 2.  In RFC3447 (PKCS#1 v2.1), the second byte is supposed
     * to be 2 regardless of which key is used.  For compatibility purposes, we'll just check to make sure the
     * second byte is 2 or less.  If it is, we'll accept the decrypted string as valid.
     *
     * As a consequence of this, a private key encrypted ciphertext produced with \phpseclib\Crypt\RSA may not decrypt
     * with a strictly PKCS#1 v1.5 compliant RSA implementation.  Public key encrypted ciphertext's should but
     * not private key encrypted ciphertext's.
     *
     * @access private
     * @param string $c
     * @return string
     */
    function _rsaes_pkcs1_v1_5_decrypt($c)
    {
        // Length checking

        if (strlen($c) != $this->k) { // or if k < 11
            user_error('Decryption error');
            return false;
        }

        // RSA decryption

        $c = $this->_os2ip($c);
        $m = $this->_rsadp($c);

        if ($m === false) {
            user_error('Decryption error');
            return false;
        }
        $em = $this->_i2osp($m, $this->k);

        // EME-PKCS1-v1_5 decoding

        if (ord($em[0]) != 0 || ord($em[1]) > 2) {
            user_error('Decryption error');
            return false;
        }

        $ps = substr($em, 2, strpos($em, chr(0), 2) - 2);
        $m = substr($em, strlen($ps) + 3);

        if (strlen($ps) < 8) {
            user_error('Decryption error');
            return false;
        }

        // Output M

        return $m;
    }

    /**
     * EMSA-PSS-ENCODE
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.1.1 RFC3447#section-9.1.1}.
     *
     * @access private
     * @param string $m
     * @param int $emBits
     */
    function _emsa_pss_encode($m, $emBits)
    {
        // if $m is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        $emLen = ($emBits + 1) >> 3; // ie. ceil($emBits / 8)
        $sLen = $this->sLen !== null ? $this->sLen : $this->hLen;

        $mHash = $this->hash->hash($m);
        if ($emLen < $this->hLen + $sLen + 2) {
            user_error('Encoding error');
            return false;
        }

        $salt = Random::string($sLen);
        $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
        $h = $this->hash->hash($m2);
        $ps = str_repeat(chr(0), $emLen - $sLen - $this->hLen - 2);
        $db = $ps . chr(1) . $salt;
        $dbMask = $this->_mgf1($h, $emLen - $this->hLen - 1);
        $maskedDB = $db ^ $dbMask;
        $maskedDB[0] = ~chr(0xFF << ($emBits & 7)) & $maskedDB[0];
        $em = $maskedDB . $h . chr(0xBC);

        return $em;
    }

    /**
     * EMSA-PSS-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.1.2 RFC3447#section-9.1.2}.
     *
     * @access private
     * @param string $m
     * @param string $em
     * @param int $emBits
     * @return string
     */
    function _emsa_pss_verify($m, $em, $emBits)
    {
        // if $m is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        $emLen = ($emBits + 7) >> 3; // ie. ceil($emBits / 8);
        $sLen = $this->sLen !== null ? $this->sLen : $this->hLen;

        $mHash = $this->hash->hash($m);
        if ($emLen < $this->hLen + $sLen + 2) {
            return false;
        }

        if ($em[strlen($em) - 1] != chr(0xBC)) {
            return false;
        }

        $maskedDB = substr($em, 0, -$this->hLen - 1);
        $h = substr($em, -$this->hLen - 1, $this->hLen);
        $temp = chr(0xFF << ($emBits & 7));
        if ((~$maskedDB[0] & $temp) != $temp) {
            return false;
        }
        $dbMask = $this->_mgf1($h, $emLen - $this->hLen - 1);
        $db = $maskedDB ^ $dbMask;
        $db[0] = ~chr(0xFF << ($emBits & 7)) & $db[0];
        $temp = $emLen - $this->hLen - $sLen - 2;
        if (substr($db, 0, $temp) != str_repeat(chr(0), $temp) || ord($db[$temp]) != 1) {
            return false;
        }
        $salt = substr($db, $temp + 1); // should be $sLen long
        $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
        $h2 = $this->hash->hash($m2);
        return $this->_equals($h, $h2);
    }

    /**
     * RSASSA-PSS-SIGN
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.1.1 RFC3447#section-8.1.1}.
     *
     * @access private
     * @param string $m
     * @return string
     */
    function _rsassa_pss_sign($m)
    {
        // EMSA-PSS encoding

        $em = $this->_emsa_pss_encode($m, 8 * $this->k - 1);

        // RSA signature

        $m = $this->_os2ip($em);
        $s = $this->_rsasp1($m);
        $s = $this->_i2osp($s, $this->k);

        // Output the signature S

        return $s;
    }

    /**
     * RSASSA-PSS-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.1.2 RFC3447#section-8.1.2}.
     *
     * @access private
     * @param string $m
     * @param string $s
     * @return string
     */
    function _rsassa_pss_verify($m, $s)
    {
        // Length checking

        if (strlen($s) != $this->k) {
            user_error('Invalid signature');
            return false;
        }

        // RSA verification

        $modBits = strlen($this->modulus->toBits());

        $s2 = $this->_os2ip($s);
        $m2 = $this->_rsavp1($s2);
        if ($m2 === false) {
            user_error('Invalid signature');
            return false;
        }
        $em = $this->_i2osp($m2, $this->k);
        if ($em === false) {
            user_error('Invalid signature');
            return false;
        }

        // EMSA-PSS verification

        return $this->_emsa_pss_verify($m, $em, $modBits - 1);
    }

    /**
     * EMSA-PKCS1-V1_5-ENCODE
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.2 RFC3447#section-9.2}.
     *
     * @access private
     * @param string $m
     * @param int $emLen
     * @return string
     */
    function _emsa_pkcs1_v1_5_encode($m, $emLen)
    {
        $h = $this->hash->hash($m);
        if ($h === false) {
            return false;
        }

        // see http://tools.ietf.org/html/rfc3447#page-43
        switch ($this->hashName) {
            case 'md2':
                $t = pack('H*', '3020300c06082a864886f70d020205000410');
                break;
            case 'md5':
                $t = pack('H*', '3020300c06082a864886f70d020505000410');
                break;
            case 'sha1':
                $t = pack('H*', '3021300906052b0e03021a05000414');
                break;
            case 'sha256':
                $t = pack('H*', '3031300d060960864801650304020105000420');
                break;
            case 'sha384':
                $t = pack('H*', '3041300d060960864801650304020205000430');
                break;
            case 'sha512':
                $t = pack('H*', '3051300d060960864801650304020305000440');
        }
        $t.= $h;
        $tLen = strlen($t);

        if ($emLen < $tLen + 11) {
            user_error('Intended encoded message length too short');
            return false;
        }

        $ps = str_repeat(chr(0xFF), $emLen - $tLen - 3);

        $em = "\0\1$ps\0$t";

        return $em;
    }

    /**
     * EMSA-PKCS1-V1_5-ENCODE (without NULL)
     *
     * Quoting https://tools.ietf.org/html/rfc8017#page-65,
     *
     * "The parameters field associated with id-sha1, id-sha224, id-sha256,
     *  id-sha384, id-sha512, id-sha512/224, and id-sha512/256 should
     *  generally be omitted, but if present, it shall have a value of type
     *  NULL"
     *
     * @access private
     * @param string $m
     * @param int $emLen
     * @return string
     */
    function _emsa_pkcs1_v1_5_encode_without_null($m, $emLen)
    {
        $h = $this->hash->hash($m);
        if ($h === false) {
            return false;
        }

        switch ($this->hashName) {
            case 'sha1':
                $t = pack('H*', '301f300706052b0e03021a0414');
                break;
            case 'sha256':
                $t = pack('H*', '302f300b06096086480165030402010420');
                break;
            case 'sha384':
                $t = pack('H*', '303f300b06096086480165030402020430');
                break;
            case 'sha512':
                $t = pack('H*', '304f300b06096086480165030402030440');
                break;
            default:
                return false;
        }
        $t.= $h;
        $tLen = strlen($t);

        if ($emLen < $tLen + 11) {
            user_error('Intended encoded message length too short');
            return false;
        }

        $ps = str_repeat(chr(0xFF), $emLen - $tLen - 3);

        $em = "\0\1$ps\0$t";

        return $em;
    }

    /**
     * RSASSA-PKCS1-V1_5-SIGN
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.2.1 RFC3447#section-8.2.1}.
     *
     * @access private
     * @param string $m
     * @return string
     */
    function _rsassa_pkcs1_v1_5_sign($m)
    {
        // EMSA-PKCS1-v1_5 encoding

        $em = $this->_emsa_pkcs1_v1_5_encode($m, $this->k);
        if ($em === false) {
            user_error('RSA modulus too short');
            return false;
        }

        // RSA signature

        $m = $this->_os2ip($em);
        $s = $this->_rsasp1($m);
        $s = $this->_i2osp($s, $this->k);

        // Output the signature S

        return $s;
    }

    /**
     * RSASSA-PKCS1-V1_5-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.2.2 RFC3447#section-8.2.2}.
     *
     * @access private
     * @param string $m
     * @param string $s
     * @return string
     */
    function _rsassa_pkcs1_v1_5_verify($m, $s)
    {
        // Length checking

        if (strlen($s) != $this->k) {
            user_error('Invalid signature');
            return false;
        }

        // RSA verification

        $s = $this->_os2ip($s);
        $m2 = $this->_rsavp1($s);
        if ($m2 === false) {
            user_error('Invalid signature');
            return false;
        }
        $em = $this->_i2osp($m2, $this->k);
        if ($em === false) {
            user_error('Invalid signature');
            return false;
        }

        // EMSA-PKCS1-v1_5 encoding

        $em2 = $this->_emsa_pkcs1_v1_5_encode($m, $this->k);
        $em3 = $this->_emsa_pkcs1_v1_5_encode_without_null($m, $this->k);

        if ($em2 === false && $em3 === false) {
            user_error('RSA modulus too short');
            return false;
        }

        // Compare

        return ($em2 !== false && $this->_equals($em, $em2)) ||
               ($em3 !== false && $this->_equals($em, $em3));
    }

    /**
     * Set Encryption Mode
     *
     * Valid values include self::ENCRYPTION_OAEP and self::ENCRYPTION_PKCS1.
     *
     * @access public
     * @param int $mode
     */
    function setEncryptionMode($mode)
    {
        $this->encryptionMode = $mode;
    }

    /**
     * Set Signature Mode
     *
     * Valid values include self::SIGNATURE_PSS and self::SIGNATURE_PKCS1
     *
     * @access public
     * @param int $mode
     */
    function setSignatureMode($mode)
    {
        $this->signatureMode = $mode;
    }

    /**
     * Set public key comment.
     *
     * @access public
     * @param string $comment
     */
    function setComment($comment)
    {
        $this->comment = $comment;
    }

    /**
     * Get public key comment.
     *
     * @access public
     * @return string
     */
    function getComment()
    {
        return $this->comment;
    }

    /**
     * Encryption
     *
     * Both self::ENCRYPTION_OAEP and self::ENCRYPTION_PKCS1 both place limits on how long $plaintext can be.
     * If $plaintext exceeds those limits it will be broken up so that it does and the resultant ciphertext's will
     * be concatenated together.
     *
     * @see self::decrypt()
     * @access public
     * @param string $plaintext
     * @return string
     */
    function encrypt($plaintext)
    {
        switch ($this->encryptionMode) {
            case self::ENCRYPTION_NONE:
                $plaintext = str_split($plaintext, $this->k);
                $ciphertext = '';
                foreach ($plaintext as $m) {
                    $ciphertext.= $this->_raw_encrypt($m);
                }
                return $ciphertext;
            case self::ENCRYPTION_PKCS1:
                $length = $this->k - 11;
                if ($length <= 0) {
                    return false;
                }

                $plaintext = str_split($plaintext, $length);
                $ciphertext = '';
                foreach ($plaintext as $m) {
                    $ciphertext.= $this->_rsaes_pkcs1_v1_5_encrypt($m);
                }
                return $ciphertext;
            //case self::ENCRYPTION_OAEP:
            default:
                $length = $this->k - 2 * $this->hLen - 2;
                if ($length <= 0) {
                    return false;
                }

                $plaintext = str_split($plaintext, $length);
                $ciphertext = '';
                foreach ($plaintext as $m) {
                    $ciphertext.= $this->_rsaes_oaep_encrypt($m);
                }
                return $ciphertext;
        }
    }

    /**
     * Decryption
     *
     * @see self::encrypt()
     * @access public
     * @param string $ciphertext
     * @return string
     */
    function decrypt($ciphertext)
    {
        if ($this->k <= 0) {
            return false;
        }

        $ciphertext = str_split($ciphertext, $this->k);
        $ciphertext[count($ciphertext) - 1] = str_pad($ciphertext[count($ciphertext) - 1], $this->k, chr(0), STR_PAD_LEFT);

        $plaintext = '';

        switch ($this->encryptionMode) {
            case self::ENCRYPTION_NONE:
                $decrypt = '_raw_encrypt';
                break;
            case self::ENCRYPTION_PKCS1:
                $decrypt = '_rsaes_pkcs1_v1_5_decrypt';
                break;
            //case self::ENCRYPTION_OAEP:
            default:
                $decrypt = '_rsaes_oaep_decrypt';
        }

        foreach ($ciphertext as $c) {
            $temp = $this->$decrypt($c);
            if ($temp === false) {
                return false;
            }
            $plaintext.= $temp;
        }

        return $plaintext;
    }

    /**
     * Create a signature
     *
     * @see self::verify()
     * @access public
     * @param string $message
     * @return string
     */
    function sign($message)
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            return false;
        }

        switch ($this->signatureMode) {
            case self::SIGNATURE_PKCS1:
                return $this->_rsassa_pkcs1_v1_5_sign($message);
            //case self::SIGNATURE_PSS:
            default:
                return $this->_rsassa_pss_sign($message);
        }
    }

    /**
     * Verifies a signature
     *
     * @see self::sign()
     * @access public
     * @param string $message
     * @param string $signature
     * @return bool
     */
    function verify($message, $signature)
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            return false;
        }

        switch ($this->signatureMode) {
            case self::SIGNATURE_PKCS1:
                return $this->_rsassa_pkcs1_v1_5_verify($message, $signature);
            //case self::SIGNATURE_PSS:
            default:
                return $this->_rsassa_pss_verify($message, $signature);
        }
    }

    /**
     * Extract raw BER from Base64 encoding
     *
     * @access private
     * @param string $str
     * @return string
     */
    function _extractBER($str)
    {
        /* X.509 certs are assumed to be base64 encoded but sometimes they'll have additional things in them
         * above and beyond the ceritificate.
         * ie. some may have the following preceding the -----BEGIN CERTIFICATE----- line:
         *
         * Bag Attributes
         *     localKeyID: 01 00 00 00
         * subject=/O=organization/OU=org unit/CN=common name
         * issuer=/O=organization/CN=common name
         */
        $temp = preg_replace('#.*?^-+[^-]+-+[\r\n ]*$#ms', '', $str, 1);
        // remove the -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- stuff
        $temp = preg_replace('#-+[^-]+-+#', '', $temp);
        // remove new lines
        $temp = str_replace(array("\r", "\n", ' '), '', $temp);
        $temp = preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $temp) ? base64_decode($temp) : false;
        return $temp != false ? $temp : $str;
    }
}


/**
 * Pure-PHP implementations of keyed-hash message authentication codes (HMACs) and various cryptographic hashing functions.
 *
 * Uses hash() or mhash() if available and an internal implementation, otherwise.  Currently supports the following:
 *
 * md2, md5, md5-96, sha1, sha1-96, sha256, sha256-96, sha384, and sha512, sha512-96
 *
 * If {@link self::setKey() setKey()} is called, {@link self::hash() hash()} will return the HMAC as opposed to
 * the hash.  If no valid algorithm is provided, sha1 will be used.
 *
 * PHP version 5
 *
 * {@internal The variable names are the same as those in
 * {@link http://tools.ietf.org/html/rfc2104#section-2 RFC2104}.}}
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $hash = new \phpseclib\Crypt\Hash('sha1');
 *
 *    $hash->setKey('abcdefg');
 *
 *    echo base64_encode($hash->hash('abcdefg'));
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   Hash
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */


/**
 * Pure-PHP implementations of keyed-hash message authentication codes (HMACs) and various cryptographic hashing functions.
 *
 * @package Hash
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class KiboboCryptHash
{
    /**#@+
     * @access private
     * @see \phpseclib\Crypt\Hash::__construct()
     */
    /**
     * Toggles the internal implementation
     */
    const MODE_INTERNAL = 1;
    /**
     * Toggles the mhash() implementation, which has been deprecated on PHP 5.3.0+.
     */
    const MODE_MHASH = 2;
    /**
     * Toggles the hash() implementation, which works on PHP 5.1.2+.
     */
    const MODE_HASH = 3;
    /**#@-*/

    /**
     * Hash Parameter
     *
     * @see self::setHash()
     * @var int
     * @access private
     */
    var $hashParam;

    /**
     * Byte-length of compression blocks / key (Internal HMAC)
     *
     * @see self::setAlgorithm()
     * @var int
     * @access private
     */
    var $b;

    /**
     * Byte-length of hash output (Internal HMAC)
     *
     * @see self::setHash()
     * @var int
     * @access private
     */
    var $l = false;

    /**
     * Hash Algorithm
     *
     * @see self::setHash()
     * @var string
     * @access private
     */
    var $hash;

    /**
     * Key
     *
     * @see self::setKey()
     * @var string
     * @access private
     */
    var $key = false;

    /**
     * Computed Key
     *
     * @see self::_computeKey()
     * @var string
     * @access private
     */
    var $computedKey = false;

    /**
     * Outer XOR (Internal HMAC)
     *
     * @see self::setKey()
     * @var string
     * @access private
     */
    var $opad;

    /**
     * Inner XOR (Internal HMAC)
     *
     * @see self::setKey()
     * @var string
     * @access private
     */
    var $ipad;

    /**
     * Engine
     *
     * @see self::setHash()
     * @var string
     * @access private
     */
    var $engine;

    /**
     * Default Constructor.
     *
     * @param string $hash
     * @return \phpseclib\Crypt\Hash
     * @access public
     */
    function __construct($hash = 'sha1')
    {
        if (!defined('CRYPT_HASH_MODE')) {
            switch (true) {
                case extension_loaded('hash'):
                    define('CRYPT_HASH_MODE', self::MODE_HASH);
                    break;
                case extension_loaded('mhash'):
                    define('CRYPT_HASH_MODE', self::MODE_MHASH);
                    break;
                default:
                    define('CRYPT_HASH_MODE', self::MODE_INTERNAL);
            }
        }

        $this->setHash($hash);
    }

    /**
     * Sets the key for HMACs
     *
     * Keys can be of any length.
     *
     * @access public
     * @param string $key
     */
    function setKey($key = false)
    {
        $this->key = $key;
        $this->_computeKey();
    }

    /**
     * Pre-compute the key used by the HMAC
     *
     * Quoting http://tools.ietf.org/html/rfc2104#section-2, "Applications that use keys longer than B bytes
     * will first hash the key using H and then use the resultant L byte string as the actual key to HMAC."
     *
     * As documented in https://www.reddit.com/r/PHP/comments/9nct2l/symfonypolyfill_hash_pbkdf2_correct_fix_for/
     * when doing an HMAC multiple times it's faster to compute the hash once instead of computing it during
     * every call
     *
     * @access private
     */
    function _computeKey()
    {
        if ($this->key === false) {
            $this->computedKey = false;
            return;
        }

        if (strlen($this->key) <= $this->b) {
            $this->computedKey = $this->key;
            return;
        }

        switch ($this->engine) {
            case self::MODE_MHASH:
                $this->computedKey = mhash($this->hash, $this->key);
                break;
            case self::MODE_HASH:
                $this->computedKey = hash($this->hash, $this->key, true);
                break;
            case self::MODE_INTERNAL:
                $this->computedKey = call_user_func($this->hash, $this->key);
        }
    }

    /**
     * Gets the hash function.
     *
     * As set by the constructor or by the setHash() method.
     *
     * @access public
     * @return string
     */
    function getHash()
    {
        return $this->hashParam;
    }

    /**
     * Sets the hash function.
     *
     * @access public
     * @param string $hash
     */
    function setHash($hash)
    {
        $this->hashParam = $hash = strtolower($hash);
        switch ($hash) {
            case 'md5-96':
            case 'sha1-96':
            case 'sha256-96':
            case 'sha512-96':
                $hash = substr($hash, 0, -3);
                $this->l = 12; // 96 / 8 = 12
                break;
            case 'md2':
            case 'md5':
                $this->l = 16;
                break;
            case 'sha1':
                $this->l = 20;
                break;
            case 'sha256':
                $this->l = 32;
                break;
            case 'sha384':
                $this->l = 48;
                break;
            case 'sha512':
                $this->l = 64;
        }

        switch ($hash) {
            case 'md2-96':
            case 'md2':
                $this->b = 16;
            case 'md5-96':
            case 'sha1-96':
            case 'sha224-96':
            case 'sha256-96':
            case 'md2':
            case 'md5':
            case 'sha1':
            case 'sha224':
            case 'sha256':
                $this->b = 64;
                break;
            default:
                $this->b = 128;
        }

        switch ($hash) {
            case 'md2':
                $this->engine = CRYPT_HASH_MODE == self::MODE_HASH && in_array('md2', hash_algos()) ?
                    self::MODE_HASH : self::MODE_INTERNAL;
                break;
            case 'sha384':
            case 'sha512':
                $this->engine = CRYPT_HASH_MODE == self::MODE_MHASH ? self::MODE_INTERNAL : CRYPT_HASH_MODE;
                break;
            default:
                $this->engine = CRYPT_HASH_MODE;
        }

        switch ($this->engine) {
            case self::MODE_MHASH:
                switch ($hash) {
                    case 'md5':
                        $this->hash = MHASH_MD5;
                        break;
                    case 'sha256':
                        $this->hash = MHASH_SHA256;
                        break;
                    case 'sha1':
                    default:
                        $this->hash = MHASH_SHA1;
                }
                $this->_computeKey(self::MODE_MHASH);
                return;
            case self::MODE_HASH:
                switch ($hash) {
                    case 'md5':
                        $this->hash = 'md5';
                        return;
                    case 'md2':
                    case 'sha256':
                    case 'sha384':
                    case 'sha512':
                        $this->hash = $hash;
                        return;
                    case 'sha1':
                    default:
                        $this->hash = 'sha1';
                }
                $this->_computeKey(self::MODE_HASH);
                return;
        }

        switch ($hash) {
            case 'md2':
                $this->hash = array($this, '_md2');
                break;
            case 'md5':
                $this->hash = array($this, '_md5');
                break;
            case 'sha256':
                $this->hash = array($this, '_sha256');
                break;
            case 'sha384':
            case 'sha512':
                $this->hash = array($this, '_sha512');
                break;
            case 'sha1':
            default:
                $this->hash = array($this, '_sha1');
        }

        $this->ipad = str_repeat(chr(0x36), $this->b);
        $this->opad = str_repeat(chr(0x5C), $this->b);

        $this->_computeKey(self::MODE_INTERNAL);
    }

    /**
     * Compute the HMAC.
     *
     * @access public
     * @param string $text
     * @return string
     */
    function hash($text)
    {
        if (!empty($this->key) || is_string($this->key)) {
            switch ($this->engine) {
                case self::MODE_MHASH:
                    $output = mhash($this->hash, $text, $this->computedKey);
                    break;
                case self::MODE_HASH:
                    $output = hash_hmac($this->hash, $text, $this->computedKey, true);
                    break;
                case self::MODE_INTERNAL:
                    $key    = str_pad($this->computedKey, $this->b, chr(0)); // step 1
                    $temp   = $this->ipad ^ $key;                            // step 2
                    $temp  .= $text;                                         // step 3
                    $temp   = call_user_func($this->hash, $temp);            // step 4
                    $output = $this->opad ^ $key;                            // step 5
                    $output.= $temp;                                         // step 6
                    $output = call_user_func($this->hash, $output);          // step 7
            }
        } else {
            switch ($this->engine) {
                case self::MODE_MHASH:
                    $output = mhash($this->hash, $text);
                    break;
                case self::MODE_HASH:
                    $output = hash($this->hash, $text, true);
                    break;
                case self::MODE_INTERNAL:
                    $output = call_user_func($this->hash, $text);
            }
        }

        return substr($output, 0, $this->l);
    }

    /**
     * Returns the hash length (in bytes)
     *
     * @access public
     * @return int
     */
    function getLength()
    {
        return $this->l;
    }

    /**
     * Wrapper for MD5
     *
     * @access private
     * @param string $m
     */
    function _md5($m)
    {
        return pack('H*', md5($m));
    }

    /**
     * Wrapper for SHA1
     *
     * @access private
     * @param string $m
     */
    function _sha1($m)
    {
        return pack('H*', sha1($m));
    }

    /**
     * Pure-PHP implementation of MD2
     *
     * See {@link http://tools.ietf.org/html/rfc1319 RFC1319}.
     *
     * @access private
     * @param string $m
     */
    function _md2($m)
    {
        static $s = array(
             41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161, 236, 240, 6,
             19,  98, 167,   5, 243, 192, 199, 115, 140, 152, 147,  43, 217, 188,
             76, 130, 202,  30, 155,  87,  60, 253, 212, 224,  22, 103,  66, 111, 24,
            138,  23, 229,  18, 190,  78, 196, 214, 218, 158, 222,  73, 160, 251,
            245, 142, 187,  47, 238, 122, 169, 104, 121, 145,  21, 178,   7,  63,
            148, 194,  16, 137,  11,  34,  95,  33, 128, 127,  93, 154,  90, 144, 50,
             39,  53,  62, 204, 231, 191, 247, 151,   3, 255,  25,  48, 179,  72, 165,
            181, 209, 215,  94, 146,  42, 172,  86, 170, 198,  79, 184,  56, 210,
            150, 164, 125, 182, 118, 252, 107, 226, 156, 116,   4, 241,  69, 157,
            112,  89, 100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2, 27,
             96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,  52,  64, 126, 15,
             85,  71, 163,  35, 221,  81, 175,  58, 195,  92, 249, 206, 186, 197,
            234,  38,  44,  83,  13, 110, 133,  40, 132,   9, 211, 223, 205, 244, 65,
            129,  77,  82, 106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,
              8,  12, 189, 177,  74, 120, 136, 149, 139, 227,  99, 232, 109, 233,
            203, 213, 254,  59,   0,  29,  57, 242, 239, 183,  14, 102,  88, 208, 228,
            166, 119, 114, 248, 235, 117,  75,  10,  49,  68,  80, 180, 143, 237,
             31,  26, 219, 153, 141,  51, 159,  17, 131, 20
        );

        // Step 1. Append Padding Bytes
        $pad = 16 - (strlen($m) & 0xF);
        $m.= str_repeat(chr($pad), $pad);

        $length = strlen($m);

        // Step 2. Append Checksum
        $c = str_repeat(chr(0), 16);
        $l = chr(0);
        for ($i = 0; $i < $length; $i+= 16) {
            for ($j = 0; $j < 16; $j++) {
                // RFC1319 incorrectly states that C[j] should be set to S[c xor L]
                //$c[$j] = chr($s[ord($m[$i + $j] ^ $l)]);
                // per <http://www.rfc-editor.org/errata_search.php?rfc=1319>, however, C[j] should be set to S[c xor L] xor C[j]
                $c[$j] = chr($s[ord($m[$i + $j] ^ $l)] ^ ord($c[$j]));
                $l = $c[$j];
            }
        }
        $m.= $c;

        $length+= 16;

        // Step 3. Initialize MD Buffer
        $x = str_repeat(chr(0), 48);

        // Step 4. Process Message in 16-Byte Blocks
        for ($i = 0; $i < $length; $i+= 16) {
            for ($j = 0; $j < 16; $j++) {
                $x[$j + 16] = $m[$i + $j];
                $x[$j + 32] = $x[$j + 16] ^ $x[$j];
            }
            $t = chr(0);
            for ($j = 0; $j < 18; $j++) {
                for ($k = 0; $k < 48; $k++) {
                    $x[$k] = $t = $x[$k] ^ chr($s[ord($t)]);
                    //$t = $x[$k] = $x[$k] ^ chr($s[ord($t)]);
                }
                $t = chr(ord($t) + $j);
            }
        }

        // Step 5. Output
        return substr($x, 0, 16);
    }

    /**
     * Pure-PHP implementation of SHA256
     *
     * See {@link http://en.wikipedia.org/wiki/SHA_hash_functions#SHA-256_.28a_SHA-2_variant.29_pseudocode SHA-256 (a SHA-2 variant) pseudocode - Wikipedia}.
     *
     * @access private
     * @param string $m
     */
    function _sha256($m)
    {
        if (extension_loaded('suhosin')) {
            return pack('H*', sha256($m));
        }

        // Initialize variables
        $hash = array(
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        );
        // Initialize table of round constants
        // (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
        static $k = array(
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        );

        // Pre-processing
        $length = strlen($m);
        // to round to nearest 56 mod 64, we'll add 64 - (length + (64 - 56)) % 64
        $m.= str_repeat(chr(0), 64 - (($length + 8) & 0x3F));
        $m[$length] = chr(0x80);
        // we don't support hashing strings 512MB long
        $m.= pack('N2', 0, $length << 3);

        // Process the message in successive 512-bit chunks
        $chunks = str_split($m, 64);
        foreach ($chunks as $chunk) {
            $w = array();
            for ($i = 0; $i < 16; $i++) {
                extract(unpack('Ntemp', $this->_string_shift($chunk, 4)));
                $w[] = $temp;
            }

            // Extend the sixteen 32-bit words into sixty-four 32-bit words
            for ($i = 16; $i < 64; $i++) {
                // @codingStandardsIgnoreStart
                $s0 = $this->_rightRotate($w[$i - 15],  7) ^
                      $this->_rightRotate($w[$i - 15], 18) ^
                      $this->_rightShift( $w[$i - 15],  3);
                $s1 = $this->_rightRotate($w[$i - 2], 17) ^
                      $this->_rightRotate($w[$i - 2], 19) ^
                      $this->_rightShift( $w[$i - 2], 10);
                // @codingStandardsIgnoreEnd
                $w[$i] = $this->_add($w[$i - 16], $s0, $w[$i - 7], $s1);
            }

            // Initialize hash value for this chunk
            list($a, $b, $c, $d, $e, $f, $g, $h) = $hash;

            // Main loop
            for ($i = 0; $i < 64; $i++) {
                $s0 = $this->_rightRotate($a,  2) ^
                      $this->_rightRotate($a, 13) ^
                      $this->_rightRotate($a, 22);
                $maj = ($a & $b) ^
                       ($a & $c) ^
                       ($b & $c);
                $t2 = $this->_add($s0, $maj);

                $s1 = $this->_rightRotate($e,  6) ^
                      $this->_rightRotate($e, 11) ^
                      $this->_rightRotate($e, 25);
                $ch = ($e & $f) ^
                      ($this->_not($e) & $g);
                $t1 = $this->_add($h, $s1, $ch, $k[$i], $w[$i]);

                $h = $g;
                $g = $f;
                $f = $e;
                $e = $this->_add($d, $t1);
                $d = $c;
                $c = $b;
                $b = $a;
                $a = $this->_add($t1, $t2);
            }

            // Add this chunk's hash to result so far
            $hash = array(
                $this->_add($hash[0], $a),
                $this->_add($hash[1], $b),
                $this->_add($hash[2], $c),
                $this->_add($hash[3], $d),
                $this->_add($hash[4], $e),
                $this->_add($hash[5], $f),
                $this->_add($hash[6], $g),
                $this->_add($hash[7], $h)
            );
        }

        // Produce the final hash value (big-endian)
        return pack('N8', $hash[0], $hash[1], $hash[2], $hash[3], $hash[4], $hash[5], $hash[6], $hash[7]);
    }

    /**
     * Pure-PHP implementation of SHA384 and SHA512
     *
     * @access private
     * @param string $m
     */
    function _sha512($m)
    {
        static $init384, $init512, $k;

        if (!isset($k)) {
            // Initialize variables
            $init384 = array( // initial values for SHA384
                'cbbb9d5dc1059ed8', '629a292a367cd507', '9159015a3070dd17', '152fecd8f70e5939',
                '67332667ffc00b31', '8eb44a8768581511', 'db0c2e0d64f98fa7', '47b5481dbefa4fa4'
            );
            $init512 = array( // initial values for SHA512
                '6a09e667f3bcc908', 'bb67ae8584caa73b', '3c6ef372fe94f82b', 'a54ff53a5f1d36f1',
                '510e527fade682d1', '9b05688c2b3e6c1f', '1f83d9abfb41bd6b', '5be0cd19137e2179'
            );

            for ($i = 0; $i < 8; $i++) {
                $init384[$i] = new KiboboCryptBigInteger($init384[$i], 16);
                $init384[$i]->setPrecision(64);
                $init512[$i] = new KiboboCryptBigInteger($init512[$i], 16);
                $init512[$i]->setPrecision(64);
            }

            // Initialize table of round constants
            // (first 64 bits of the fractional parts of the cube roots of the first 80 primes 2..409)
            $k = array(
                '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc',
                '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
                'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2',
                '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
                'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
                '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
                '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4',
                'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
                '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df',
                '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
                'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30',
                'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
                '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8',
                '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
                '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
                '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
                'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178',
                '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
                '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c',
                '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817'
            );

            for ($i = 0; $i < 80; $i++) {
                $k[$i] = new KiboboCryptBigInteger($k[$i], 16);
            }
        }

        $hash = $this->l == 48 ? $init384 : $init512;

        // Pre-processing
        $length = strlen($m);
        // to round to nearest 112 mod 128, we'll add 128 - (length + (128 - 112)) % 128
        $m.= str_repeat(chr(0), 128 - (($length + 16) & 0x7F));
        $m[$length] = chr(0x80);
        // we don't support hashing strings 512MB long
        $m.= pack('N4', 0, 0, 0, $length << 3);

        // Process the message in successive 1024-bit chunks
        $chunks = str_split($m, 128);
        foreach ($chunks as $chunk) {
            $w = array();
            for ($i = 0; $i < 16; $i++) {
                $temp = new KiboboCryptBigInteger($this->_string_shift($chunk, 8), 256);
                $temp->setPrecision(64);
                $w[] = $temp;
            }

            // Extend the sixteen 32-bit words into eighty 32-bit words
            for ($i = 16; $i < 80; $i++) {
                $temp = array(
                          $w[$i - 15]->bitwise_rightRotate(1),
                          $w[$i - 15]->bitwise_rightRotate(8),
                          $w[$i - 15]->bitwise_rightShift(7)
                );
                $s0 = $temp[0]->bitwise_xor($temp[1]);
                $s0 = $s0->bitwise_xor($temp[2]);
                $temp = array(
                          $w[$i - 2]->bitwise_rightRotate(19),
                          $w[$i - 2]->bitwise_rightRotate(61),
                          $w[$i - 2]->bitwise_rightShift(6)
                );
                $s1 = $temp[0]->bitwise_xor($temp[1]);
                $s1 = $s1->bitwise_xor($temp[2]);
                $w[$i] = $w[$i - 16]->copy();
                $w[$i] = $w[$i]->add($s0);
                $w[$i] = $w[$i]->add($w[$i - 7]);
                $w[$i] = $w[$i]->add($s1);
            }

            // Initialize hash value for this chunk
            $a = $hash[0]->copy();
            $b = $hash[1]->copy();
            $c = $hash[2]->copy();
            $d = $hash[3]->copy();
            $e = $hash[4]->copy();
            $f = $hash[5]->copy();
            $g = $hash[6]->copy();
            $h = $hash[7]->copy();

            // Main loop
            for ($i = 0; $i < 80; $i++) {
                $temp = array(
                    $a->bitwise_rightRotate(28),
                    $a->bitwise_rightRotate(34),
                    $a->bitwise_rightRotate(39)
                );
                $s0 = $temp[0]->bitwise_xor($temp[1]);
                $s0 = $s0->bitwise_xor($temp[2]);
                $temp = array(
                    $a->bitwise_and($b),
                    $a->bitwise_and($c),
                    $b->bitwise_and($c)
                );
                $maj = $temp[0]->bitwise_xor($temp[1]);
                $maj = $maj->bitwise_xor($temp[2]);
                $t2 = $s0->add($maj);

                $temp = array(
                    $e->bitwise_rightRotate(14),
                    $e->bitwise_rightRotate(18),
                    $e->bitwise_rightRotate(41)
                );
                $s1 = $temp[0]->bitwise_xor($temp[1]);
                $s1 = $s1->bitwise_xor($temp[2]);
                $temp = array(
                    $e->bitwise_and($f),
                    $g->bitwise_and($e->bitwise_not())
                );
                $ch = $temp[0]->bitwise_xor($temp[1]);
                $t1 = $h->add($s1);
                $t1 = $t1->add($ch);
                $t1 = $t1->add($k[$i]);
                $t1 = $t1->add($w[$i]);

                $h = $g->copy();
                $g = $f->copy();
                $f = $e->copy();
                $e = $d->add($t1);
                $d = $c->copy();
                $c = $b->copy();
                $b = $a->copy();
                $a = $t1->add($t2);
            }

            // Add this chunk's hash to result so far
            $hash = array(
                $hash[0]->add($a),
                $hash[1]->add($b),
                $hash[2]->add($c),
                $hash[3]->add($d),
                $hash[4]->add($e),
                $hash[5]->add($f),
                $hash[6]->add($g),
                $hash[7]->add($h)
            );
        }

        // Produce the final hash value (big-endian)
        // (\phpseclib\Crypt\Hash::hash() trims the output for hashes but not for HMACs.  as such, we trim the output here)
        $temp = $hash[0]->toBytes() . $hash[1]->toBytes() . $hash[2]->toBytes() . $hash[3]->toBytes() .
                $hash[4]->toBytes() . $hash[5]->toBytes();
        if ($this->l != 48) {
            $temp.= $hash[6]->toBytes() . $hash[7]->toBytes();
        }

        return $temp;
    }

    /**
     * Right Rotate
     *
     * @access private
     * @param int $int
     * @param int $amt
     * @see self::_sha256()
     * @return int
     */
    function _rightRotate($int, $amt)
    {
        $invamt = 32 - $amt;
        $mask = (1 << $invamt) - 1;
        return (($int << $invamt) & 0xFFFFFFFF) | (($int >> $amt) & $mask);
    }

    /**
     * Right Shift
     *
     * @access private
     * @param int $int
     * @param int $amt
     * @see self::_sha256()
     * @return int
     */
    function _rightShift($int, $amt)
    {
        $mask = (1 << (32 - $amt)) - 1;
        return ($int >> $amt) & $mask;
    }

    /**
     * Not
     *
     * @access private
     * @param int $int
     * @see self::_sha256()
     * @return int
     */
    function _not($int)
    {
        return ~$int & 0xFFFFFFFF;
    }

    /**
     * Add
     *
     * _sha256() adds multiple unsigned 32-bit integers.  Since PHP doesn't support unsigned integers and since the
     * possibility of overflow exists, care has to be taken.  BigInteger could be used but this should be faster.
     *
     * @return int
     * @see self::_sha256()
     * @access private
     */
    function _add()
    {
        static $mod;
        if (!isset($mod)) {
            $mod = pow(2, 32);
        }

        $result = 0;
        $arguments = func_get_args();
        foreach ($arguments as $argument) {
            $result+= $argument < 0 ? ($argument & 0x7FFFFFFF) + 0x80000000 : $argument;
        }

        if ((php_uname('m') & "\xDF\xDF\xDF") != 'ARM') {
            return fmod($result, $mod);
        }

        return (fmod($result, 0x80000000) & 0x7FFFFFFF) |
            ((fmod(floor($result / 0x80000000), 2) & 1) << 31);
    }

    /**
     * String Shift
     *
     * Inspired by array_shift
     *
     * @param string $string
     * @param int $index
     * @return string
     * @access private
     */
    function _string_shift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }
}

/**
 * Random Number Generator
 *
 * PHP version 5
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    echo bin2hex(\phpseclib\Crypt\Random::string(8));
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   Random
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

/**
 * Pure-PHP Random Number Generator
 *
 * @package Random
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class KiboboCryptRandom
{
    /**
     * Generate a random string.
     *
     * Although microoptimizations are generally discouraged as they impair readability this function is ripe with
     * microoptimizations because this function has the potential of being called a huge number of times.
     * eg. for RSA key generation.
     *
     * @param int $length
     * @return string
     */
    static function string($length)
    {
        if (!$length) {
            return '';
        }

        if (version_compare(PHP_VERSION, '7.0.0', '>=')) {
            try {
                return \random_bytes($length);
            } catch (\Throwable $e) {
                // If a sufficient source of randomness is unavailable, random_bytes() will throw an
                // object that implements the Throwable interface (Exception, TypeError, Error).
                // We don't actually need to do anything here. The string() method should just continue
                // as normal. Note, however, that if we don't have a sufficient source of randomness for
                // random_bytes(), most of the other calls here will fail too, so we'll end up using
                // the PHP implementation.
            }
        }

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            // method 1. prior to PHP 5.3 this would call rand() on windows hence the function_exists('class_alias') call.
            // ie. class_alias is a function that was introduced in PHP 5.3
            if (extension_loaded('mcrypt') && function_exists('class_alias')) {
                return @mcrypt_create_iv($length);
            }
            // method 2. openssl_random_pseudo_bytes was introduced in PHP 5.3.0 but prior to PHP 5.3.4 there was,
            // to quote <http://php.net/ChangeLog-5.php#5.3.4>, "possible blocking behavior". as of 5.3.4
            // openssl_random_pseudo_bytes and mcrypt_create_iv do the exact same thing on Windows. ie. they both
            // call php_win32_get_random_bytes():
            //
            // https://github.com/php/php-src/blob/7014a0eb6d1611151a286c0ff4f2238f92c120d6/ext/openssl/openssl.c#L5008
            // https://github.com/php/php-src/blob/7014a0eb6d1611151a286c0ff4f2238f92c120d6/ext/mcrypt/mcrypt.c#L1392
            //
            // php_win32_get_random_bytes() is defined thusly:
            //
            // https://github.com/php/php-src/blob/7014a0eb6d1611151a286c0ff4f2238f92c120d6/win32/winutil.c#L80
            //
            // we're calling it, all the same, in the off chance that the mcrypt extension is not available
            if (extension_loaded('openssl') && version_compare(PHP_VERSION, '5.3.4', '>=')) {
                return openssl_random_pseudo_bytes($length);
            }
        } else {
            // method 1. the fastest
            if (extension_loaded('openssl')) {
                return openssl_random_pseudo_bytes($length);
            }
            // method 2
            static $fp = true;
            if ($fp === true) {
                // warning's will be output unles the error suppression operator is used. errors such as
                // "open_basedir restriction in effect", "Permission denied", "No such file or directory", etc.
                $fp = @fopen('/dev/urandom', 'rb');
            }
            if ($fp !== true && $fp !== false) { // surprisingly faster than !is_bool() or is_resource()
                $temp = fread($fp, $length);
                if (strlen($temp) == $length) {
                    return $temp;
                }
            }
            // method 3. pretty much does the same thing as method 2 per the following url:
            // https://github.com/php/php-src/blob/7014a0eb6d1611151a286c0ff4f2238f92c120d6/ext/mcrypt/mcrypt.c#L1391
            // surprisingly slower than method 2. maybe that's because mcrypt_create_iv does a bunch of error checking that we're
            // not doing. regardless, this'll only be called if this PHP script couldn't open /dev/urandom due to open_basedir
            // restrictions or some such
            if (extension_loaded('mcrypt')) {
                return @mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
            }
        }
        // at this point we have no choice but to use a pure-PHP CSPRNG

        // cascade entropy across multiple PHP instances by fixing the session and collecting all
        // environmental variables, including the previous session data and the current session
        // data.
        //
        // mt_rand seeds itself by looking at the PID and the time, both of which are (relatively)
        // easy to guess at. linux uses mouse clicks, keyboard timings, etc, as entropy sources, but
        // PHP isn't low level to be able to use those as sources and on a web server there's not likely
        // going to be a ton of keyboard or mouse action. web servers do have one thing that we can use
        // however, a ton of people visiting the website. obviously you don't want to base your seeding
        // soley on parameters a potential attacker sends but (1) not everything in $_SERVER is controlled
        // by the user and (2) this isn't just looking at the data sent by the current user - it's based
        // on the data sent by all users. one user requests the page and a hash of their info is saved.
        // another user visits the page and the serialization of their data is utilized along with the
        // server envirnment stuff and a hash of the previous http request data (which itself utilizes
        // a hash of the session data before that). certainly an attacker should be assumed to have
        // full control over his own http requests. he, however, is not going to have control over
        // everyone's http requests.
        static $crypto = false, $v;
        if ($crypto === false) {
            // save old session data
            $old_session_id = session_id();
            $old_use_cookies = ini_get('session.use_cookies');
            $old_session_cache_limiter = session_cache_limiter();
            $_OLD_SESSION = isset($_SESSION) ? $_SESSION : false;
            if ($old_session_id != '') {
                session_write_close();
            }

            session_id(1);
            ini_set('session.use_cookies', 0);
            session_cache_limiter('');
            session_start();

            $v = $seed = $_SESSION['seed'] = pack('H*', sha1(
                (isset($_SERVER) ? phpseclib_safe_serialize($_SERVER) : '') .
                (isset($_POST) ? phpseclib_safe_serialize($_POST) : '') .
                (isset($_GET) ? phpseclib_safe_serialize($_GET) : '') .
                (isset($_COOKIE) ? phpseclib_safe_serialize($_COOKIE) : '') .
                // as of PHP 8.1 $GLOBALS cann't be accessed by reference, which eliminates
                // the need for phpseclib_safe_serialize. see https://wiki.php.net/rfc/restrict_globals_usage
                // for more info
                (version_compare(PHP_VERSION, '8.1.0', '>=') ? serialize($GLOBALS) : phpseclib_safe_serialize($GLOBALS)) .
                phpseclib_safe_serialize($_SESSION) .
                phpseclib_safe_serialize($_OLD_SESSION)
            ));
            if (!isset($_SESSION['count'])) {
                $_SESSION['count'] = 0;
            }
            $_SESSION['count']++;

            session_write_close();

            // restore old session data
            if ($old_session_id != '') {
                session_id($old_session_id);
                session_start();
                ini_set('session.use_cookies', $old_use_cookies);
                session_cache_limiter($old_session_cache_limiter);
            } else {
                if ($_OLD_SESSION !== false) {
                    $_SESSION = $_OLD_SESSION;
                    unset($_OLD_SESSION);
                } else {
                    unset($_SESSION);
                }
            }

            // in SSH2 a shared secret and an exchange hash are generated through the key exchange process.
            // the IV client to server is the hash of that "nonce" with the letter A and for the encryption key it's the letter C.
            // if the hash doesn't produce enough a key or an IV that's long enough concat successive hashes of the
            // original hash and the current hash. we'll be emulating that. for more info see the following URL:
            //
            // http://tools.ietf.org/html/rfc4253#section-7.2
            //
            // see the is_string($crypto) part for an example of how to expand the keys
            $key = pack('H*', sha1($seed . 'A'));
            $iv = pack('H*', sha1($seed . 'C'));

            // ciphers are used as per the nist.gov link below. also, see this link:
            //
            // http://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator#Designs_based_on_cryptographic_primitives
            switch (true) {
                case class_exists('\phpseclib\Crypt\AES'):
                    $crypto = new KiboboCryptAES(KiboboCryptBase::MODE_CTR);
                    break;
                case class_exists('\phpseclib\Crypt\Twofish'):
                    $crypto = new Twofish(KiboboCryptBase::MODE_CTR);
                    break;
                case class_exists('\phpseclib\Crypt\Blowfish'):
                    $crypto = new Blowfish(KiboboCryptBase::MODE_CTR);
                    break;
                case class_exists('\phpseclib\Crypt\TripleDES'):
                    $crypto = new TripleDES(KiboboCryptBase::MODE_CTR);
                    break;
                case class_exists('\phpseclib\Crypt\DES'):
                    $crypto = new DES(KiboboCryptBase::MODE_CTR);
                    break;
                case class_exists('\phpseclib\Crypt\RC4'):
                    $crypto = new RC4();
                    break;
                default:
                    user_error(__CLASS__ . ' requires at least one symmetric cipher be loaded');
                    return false;
            }

            $crypto->setKey($key);
            $crypto->setIV($iv);
            $crypto->enableContinuousBuffer();
        }

        //return $crypto->encrypt(str_repeat("\0", $length));

        // the following is based off of ANSI X9.31:
        //
        // http://csrc.nist.gov/groups/STM/cavp/documents/rng/931rngext.pdf
        //
        // OpenSSL uses that same standard for it's random numbers:
        //
        // http://www.opensource.apple.com/source/OpenSSL/OpenSSL-38/openssl/fips-1.0/rand/fips_rand.c
        // (do a search for "ANS X9.31 A.2.4")
        $result = '';
        while (strlen($result) < $length) {
            $i = $crypto->encrypt(microtime()); // strlen(microtime()) == 21
            $r = $crypto->encrypt($i ^ $v); // strlen($v) == 20
            $v = $crypto->encrypt($r ^ $i); // strlen($r) == 20
            $result.= $r;
        }
        return substr($result, 0, $length);
    }
}

if (!function_exists('phpseclib_safe_serialize')) {
    /**
     * Safely serialize variables
     *
     * If a class has a private __sleep() method it'll give a fatal error on PHP 5.2 and earlier.
     * PHP 5.3 will emit a warning.
     *
     * @param mixed $arr
     * @access public
     */
    function phpseclib_safe_serialize(&$arr)
    {
        if (is_object($arr)) {
            return '';
        }
        if (!is_array($arr)) {
            return serialize($arr);
        }
        // prevent circular array recursion
        if (isset($arr['__phpseclib_marker'])) {
            return '';
        }
        $safearr = array();
        $arr['__phpseclib_marker'] = true;
        foreach (array_keys($arr) as $key) {
            // do not recurse on the '__phpseclib_marker' key itself, for smaller memory usage
            if ($key !== '__phpseclib_marker') {
                $safearr[$key] = phpseclib_safe_serialize($arr[$key]);
            }
        }
        unset($arr['__phpseclib_marker']);
        return serialize($safearr);
    }
}

/**
 * Pure-PHP arbitrary precision integer arithmetic library.
 *
 * Supports base-2, base-10, base-16, and base-256 numbers.  Uses the GMP or BCMath extensions, if available,
 * and an internal implementation, otherwise.
 *
 * PHP version 5
 *
 * {@internal (all DocBlock comments regarding implementation - such as the one that follows - refer to the
 * {@link self::MODE_INTERNAL self::MODE_INTERNAL} mode)
 *
 * BigInteger uses base-2**26 to perform operations such as multiplication and division and
 * base-2**52 (ie. two base 2**26 digits) to perform addition and subtraction.  Because the largest possible
 * value when multiplying two base-2**26 numbers together is a base-2**52 number, double precision floating
 * point numbers - numbers that should be supported on most hardware and whose significand is 53 bits - are
 * used.  As a consequence, bitwise operators such as >> and << cannot be used, nor can the modulo operator %,
 * which only supports integers.  Although this fact will slow this library down, the fact that such a high
 * base is being used should more than compensate.
 *
 * Numbers are stored in {@link http://en.wikipedia.org/wiki/Endianness little endian} format.  ie.
 * (new \phpseclib\Math\BigInteger(pow(2, 26)))->value = array(0, 1)
 *
 * Useful resources are as follows:
 *
 *  - {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf Handbook of Applied Cryptography (HAC)}
 *  - {@link http://math.libtomcrypt.com/files/tommath.pdf Multi-Precision Math (MPM)}
 *  - Java's BigInteger classes.  See /j2se/src/share/classes/java/math in jdk-1_5_0-src-jrl.zip
 *
 * Here's an example of how to use this library:
 * <code>
 * <?php
 *    $a = new \phpseclib\Math\BigInteger(2);
 *    $b = new \phpseclib\Math\BigInteger(3);
 *
 *    $c = $a->add($b);
 *
 *    echo $c->toString(); // outputs 5
 * ?>
 * </code>
 *
 * @category  Math
 * @package   BigInteger
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2006 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */


/**
 * Pure-PHP arbitrary precision integer arithmetic library. Supports base-2, base-10, base-16, and base-256
 * numbers.
 *
 * @package BigInteger
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class KiboboCryptBigInteger
{
    /**#@+
     * Reduction constants
     *
     * @access private
     * @see BigInteger::_reduce()
     */
    /**
     * @see BigInteger::_montgomery()
     * @see BigInteger::_prepMontgomery()
     */
    const MONTGOMERY = 0;
    /**
     * @see BigInteger::_barrett()
     */
    const BARRETT = 1;
    /**
     * @see BigInteger::_mod2()
     */
    const POWEROF2 = 2;
    /**
     * @see BigInteger::_remainder()
     */
    const CLASSIC = 3;
    /**
     * @see BigInteger::__clone()
     */
    const NONE = 4;
    /**#@-*/

    /**#@+
     * Array constants
     *
     * Rather than create a thousands and thousands of new BigInteger objects in repeated function calls to add() and
     * multiply() or whatever, we'll just work directly on arrays, taking them in as parameters and returning them.
     *
     * @access private
    */
    /**
     * $result[self::VALUE] contains the value.
     */
    const VALUE = 0;
    /**
     * $result[self::SIGN] contains the sign.
     */
    const SIGN = 1;
    /**#@-*/

    /**#@+
     * @access private
     * @see BigInteger::_montgomery()
     * @see BigInteger::_barrett()
    */
    /**
     * Cache constants
     *
     * $cache[self::VARIABLE] tells us whether or not the cached data is still valid.
     */
    const VARIABLE = 0;
    /**
     * $cache[self::DATA] contains the cached data.
     */
    const DATA = 1;
    /**#@-*/

    /**#@+
     * Mode constants.
     *
     * @access private
     * @see BigInteger::__construct()
    */
    /**
     * To use the pure-PHP implementation
     */
    const MODE_INTERNAL = 1;
    /**
     * To use the BCMath library
     *
     * (if enabled; otherwise, the internal implementation will be used)
     */
    const MODE_BCMATH = 2;
    /**
     * To use the GMP library
     *
     * (if present; otherwise, either the BCMath or the internal implementation will be used)
     */
    const MODE_GMP = 3;
    /**#@-*/

    /**
     * Karatsuba Cutoff
     *
     * At what point do we switch between Karatsuba multiplication and schoolbook long multiplication?
     *
     * @access private
     */
    const KARATSUBA_CUTOFF = 25;

    /**#@+
     * Static properties used by the pure-PHP implementation.
     *
     * @see __construct()
     */
    protected static $base;
    protected static $baseFull;
    protected static $maxDigit;
    protected static $msb;

    /**
     * $max10 in greatest $max10Len satisfying
     * $max10 = 10**$max10Len <= 2**$base.
     */
    protected static $max10;

    /**
     * $max10Len in greatest $max10Len satisfying
     * $max10 = 10**$max10Len <= 2**$base.
     */
    protected static $max10Len;
    protected static $maxDigit2;
    /**#@-*/

    /**
     * Holds the BigInteger's value.
     *
     * @var array
     * @access private
     */
    var $value;

    /**
     * Holds the BigInteger's magnitude.
     *
     * @var bool
     * @access private
     */
    var $is_negative = false;

    /**
     * Precision
     *
     * @see self::setPrecision()
     * @access private
     */
    var $precision = -1;

    /**
     * Precision Bitmask
     *
     * @see self::setPrecision()
     * @access private
     */
    var $bitmask = false;

    /**
     * Mode independent value used for serialization.
     *
     * If the bcmath or gmp extensions are installed $this->value will be a non-serializable resource, hence the need for
     * a variable that'll be serializable regardless of whether or not extensions are being used.  Unlike $this->value,
     * however, $this->hex is only calculated when $this->__sleep() is called.
     *
     * @see self::__sleep()
     * @see self::__wakeup()
     * @var string
     * @access private
     */
    var $hex;

    /**
     * Converts base-2, base-10, base-16, and binary strings (base-256) to BigIntegers.
     *
     * If the second parameter - $base - is negative, then it will be assumed that the number's are encoded using
     * two's compliment.  The sole exception to this is -10, which is treated the same as 10 is.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger('0x32', 16); // 50 in base-16
     *
     *    echo $a->toString(); // outputs 50
     * ?>
     * </code>
     *
     * @param int|string|resource $x base-10 number or base-$base number if $base set.
     * @param int $base
     * @return \phpseclib\Math\BigInteger
     * @access public
     */
    function __construct($x = 0, $base = 10)
    {
        if (!defined('MATH_BIGINTEGER_MODE')) {
            switch (true) {
                case extension_loaded('gmp'):
                    define('MATH_BIGINTEGER_MODE', self::MODE_GMP);
                    break;
                case extension_loaded('bcmath'):
                    define('MATH_BIGINTEGER_MODE', self::MODE_BCMATH);
                    break;
                default:
                    define('MATH_BIGINTEGER_MODE', self::MODE_INTERNAL);
            }
        }

        if (extension_loaded('openssl') && !defined('MATH_BIGINTEGER_OPENSSL_DISABLE') && !defined('MATH_BIGINTEGER_OPENSSL_ENABLED')) {
            // some versions of XAMPP have mismatched versions of OpenSSL which causes it not to work
            $versions = array();

            // avoid generating errors (even with suppression) when phpinfo() is disabled (common in production systems)
            if (function_exists('phpinfo')) {
                ob_start();
                @phpinfo();
                $content = ob_get_contents();
                ob_end_clean();

                preg_match_all('#OpenSSL (Header|Library) Version(.*)#im', $content, $matches);

                if (!empty($matches[1])) {
                    for ($i = 0; $i < count($matches[1]); $i++) {
                        $fullVersion = trim(str_replace('=>', '', strip_tags($matches[2][$i])));

                        // Remove letter part in OpenSSL version
                        if (!preg_match('/(\d+\.\d+\.\d+)/i', $fullVersion, $m)) {
                            $versions[$matches[1][$i]] = $fullVersion;
                        } else {
                            $versions[$matches[1][$i]] = $m[0];
                        }
                    }
                }
            }

            // it doesn't appear that OpenSSL versions were reported upon until PHP 5.3+
            switch (true) {
                case !isset($versions['Header']):
                case !isset($versions['Library']):
                case $versions['Header'] == $versions['Library']:
                case version_compare($versions['Header'], '1.0.0') >= 0 && version_compare($versions['Library'], '1.0.0') >= 0:
                    define('MATH_BIGINTEGER_OPENSSL_ENABLED', true);
                    break;
                default:
                    define('MATH_BIGINTEGER_OPENSSL_DISABLE', true);
            }
        }

        if (!defined('PHP_INT_SIZE')) {
            define('PHP_INT_SIZE', 4);
        }

        if (empty(self::$base) && MATH_BIGINTEGER_MODE == self::MODE_INTERNAL) {
            switch (PHP_INT_SIZE) {
                case 8: // use 64-bit integers if int size is 8 bytes
                    self::$base      = 31;
                    self::$baseFull  = 0x80000000;
                    self::$maxDigit  = 0x7FFFFFFF;
                    self::$msb       = 0x40000000;
                    self::$max10     = 1000000000;
                    self::$max10Len  = 9;
                    self::$maxDigit2 = pow(2, 62);
                    break;
                //case 4: // use 64-bit floats if int size is 4 bytes
                default:
                    self::$base      = 26;
                    self::$baseFull  = 0x4000000;
                    self::$maxDigit  = 0x3FFFFFF;
                    self::$msb       = 0x2000000;
                    self::$max10     = 10000000;
                    self::$max10Len  = 7;
                    self::$maxDigit2 = pow(2, 52); // pow() prevents truncation
            }
        }

        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                switch (true) {
                    case is_resource($x) && get_resource_type($x) == 'GMP integer':
                    // PHP 5.6 switched GMP from using resources to objects
                    case $x instanceof \GMP:
                        $this->value = $x;
                        return;
                }
                $this->value = gmp_init(0);
                break;
            case self::MODE_BCMATH:
                $this->value = '0';
                break;
            default:
                $this->value = array();
        }

        // '0' counts as empty() but when the base is 256 '0' is equal to ord('0') or 48
        // '0' is the only value like this per http://php.net/empty
        if (empty($x) && (abs($base) != 256 || $x !== '0')) {
            return;
        }

        switch ($base) {
            case -256:
                if (ord($x[0]) & 0x80) {
                    $x = ~$x;
                    $this->is_negative = true;
                }
            case 256:
                switch (MATH_BIGINTEGER_MODE) {
                    case self::MODE_GMP:
                        $this->value = function_exists('gmp_import') ?
                            gmp_import($x) :
                            gmp_init('0x' . bin2hex($x));
                        if ($this->is_negative) {
                            $this->value = gmp_neg($this->value);
                        }
                        break;
                    case self::MODE_BCMATH:
                        // round $len to the nearest 4 (thanks, DavidMJ!)
                        $len = (strlen($x) + 3) & ~3;

                        $x = str_pad($x, $len, chr(0), STR_PAD_LEFT);

                        for ($i = 0; $i < $len; $i+= 4) {
                            $this->value = bcmul($this->value, '4294967296', 0); // 4294967296 == 2**32
                            $this->value = bcadd($this->value, 0x1000000 * ord($x[$i]) + ((ord($x[$i + 1]) << 16) | (ord($x[$i + 2]) << 8) | ord($x[$i + 3])), 0);
                        }

                        if ($this->is_negative) {
                            $this->value = '-' . $this->value;
                        }

                        break;
                    // converts a base-2**8 (big endian / msb) number to base-2**26 (little endian / lsb)
                    default:
                        while (strlen($x)) {
                            $this->value[] = $this->_bytes2int($this->_base256_rshift($x, self::$base));
                        }
                }

                if ($this->is_negative) {
                    if (MATH_BIGINTEGER_MODE != self::MODE_INTERNAL) {
                        $this->is_negative = false;
                    }
                    $temp = $this->add(new static('-1'));
                    $this->value = $temp->value;
                }
                break;
            case 16:
            case -16:
                if ($base > 0 && $x[0] == '-') {
                    $this->is_negative = true;
                    $x = substr($x, 1);
                }

                $x = preg_replace('#^(?:0x)?([A-Fa-f0-9]*).*#', '$1', $x);

                $is_negative = false;
                if ($base < 0 && hexdec($x[0]) >= 8) {
                    $this->is_negative = $is_negative = true;
                    $x = bin2hex(~pack('H*', $x));
                }

                switch (MATH_BIGINTEGER_MODE) {
                    case self::MODE_GMP:
                        $temp = $this->is_negative ? '-0x' . $x : '0x' . $x;
                        $this->value = gmp_init($temp);
                        $this->is_negative = false;
                        break;
                    case self::MODE_BCMATH:
                        $x = (strlen($x) & 1) ? '0' . $x : $x;
                        $temp = new static(pack('H*', $x), 256);
                        $this->value = $this->is_negative ? '-' . $temp->value : $temp->value;
                        $this->is_negative = false;
                        break;
                    default:
                        $x = (strlen($x) & 1) ? '0' . $x : $x;
                        $temp = new static(pack('H*', $x), 256);
                        $this->value = $temp->value;
                }

                if ($is_negative) {
                    $temp = $this->add(new static('-1'));
                    $this->value = $temp->value;
                }
                break;
            case 10:
            case -10:
                // (?<!^)(?:-).*: find any -'s that aren't at the beginning and then any characters that follow that
                // (?<=^|-)0*: find any 0's that are preceded by the start of the string or by a - (ie. octals)
                // [^-0-9].*: find any non-numeric characters and then any characters that follow that
                $x = preg_replace('#(?<!^)(?:-).*|(?<=^|-)0*|[^-0-9].*#', '', $x);
                if (!strlen($x) || $x == '-') {
                    $x = '0';
                }

                switch (MATH_BIGINTEGER_MODE) {
                    case self::MODE_GMP:
                        $this->value = gmp_init($x);
                        break;
                    case self::MODE_BCMATH:
                        // explicitly casting $x to a string is necessary, here, since doing $x[0] on -1 yields different
                        // results then doing it on '-1' does (modInverse does $x[0])
                        $this->value = $x === '-' ? '0' : (string) $x;
                        break;
                    default:
                        $temp = new static();

                        $multiplier = new static();
                        $multiplier->value = array(self::$max10);

                        if ($x[0] == '-') {
                            $this->is_negative = true;
                            $x = substr($x, 1);
                        }

                        $x = str_pad($x, strlen($x) + ((self::$max10Len - 1) * strlen($x)) % self::$max10Len, 0, STR_PAD_LEFT);
                        while (strlen($x)) {
                            $temp = $temp->multiply($multiplier);
                            $temp = $temp->add(new static($this->_int2bytes(substr($x, 0, self::$max10Len)), 256));
                            $x = substr($x, self::$max10Len);
                        }

                        $this->value = $temp->value;
                }
                break;
            case 2: // base-2 support originally implemented by Lluis Pamies - thanks!
            case -2:
                if ($base > 0 && $x[0] == '-') {
                    $this->is_negative = true;
                    $x = substr($x, 1);
                }

                $x = preg_replace('#^([01]*).*#', '$1', $x);
                $x = str_pad($x, strlen($x) + (3 * strlen($x)) % 4, 0, STR_PAD_LEFT);

                $str = '0x';
                while (strlen($x)) {
                    $part = substr($x, 0, 4);
                    $str.= dechex(bindec($part));
                    $x = substr($x, 4);
                }

                if ($this->is_negative) {
                    $str = '-' . $str;
                }

                $temp = new static($str, 8 * $base); // ie. either -16 or +16
                $this->value = $temp->value;
                $this->is_negative = $temp->is_negative;

                break;
            default:
                // base not supported, so we'll let $this == 0
        }
    }

    /**
     * Converts a BigInteger to a byte string (eg. base-256).
     *
     * Negative numbers are saved as positive numbers, unless $twos_compliment is set to true, at which point, they're
     * saved as two's compliment.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger('65');
     *
     *    echo $a->toBytes(); // outputs chr(65)
     * ?>
     * </code>
     *
     * @param bool $twos_compliment
     * @return string
     * @access public
     * @internal Converts a base-2**26 number to base-2**8
     */
    function toBytes($twos_compliment = false)
    {
        if ($twos_compliment) {
            $comparison = $this->compare(new static());
            if ($comparison == 0) {
                return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
            }

            $temp = $comparison < 0 ? $this->add(new static(1)) : $this->copy();
            $bytes = $temp->toBytes();

            if (!strlen($bytes)) { // eg. if the number we're trying to convert is -1
                $bytes = chr(0);
            }

            if ($this->precision <= 0 && (ord($bytes[0]) & 0x80)) {
                $bytes = chr(0) . $bytes;
            }

            return $comparison < 0 ? ~$bytes : $bytes;
        }

        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                if (gmp_cmp($this->value, gmp_init(0)) == 0) {
                    return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
                }

                if (function_exists('gmp_export')) {
                    $temp = gmp_export($this->value);
                } else {
                    $temp = gmp_strval(gmp_abs($this->value), 16);
                    $temp = (strlen($temp) & 1) ? '0' . $temp : $temp;
                    $temp = pack('H*', $temp);
                }

                return $this->precision > 0 ?
                    substr(str_pad($temp, $this->precision >> 3, chr(0), STR_PAD_LEFT), -($this->precision >> 3)) :
                    ltrim($temp, chr(0));
            case self::MODE_BCMATH:
                if ($this->value === '0') {
                    return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
                }

                $value = '';
                $current = $this->value;

                if ($current[0] == '-') {
                    $current = substr($current, 1);
                }

                while (bccomp($current, '0', 0) > 0) {
                    $temp = bcmod($current, '16777216');
                    $value = chr($temp >> 16) . chr($temp >> 8) . chr($temp) . $value;
                    $current = bcdiv($current, '16777216', 0);
                }

                return $this->precision > 0 ?
                    substr(str_pad($value, $this->precision >> 3, chr(0), STR_PAD_LEFT), -($this->precision >> 3)) :
                    ltrim($value, chr(0));
        }

        if (!count($this->value)) {
            return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
        }
        $result = $this->_int2bytes($this->value[count($this->value) - 1]);

        $temp = $this->copy();

        for ($i = count($temp->value) - 2; $i >= 0; --$i) {
            $temp->_base256_lshift($result, self::$base);
            $result = $result | str_pad($temp->_int2bytes($temp->value[$i]), strlen($result), chr(0), STR_PAD_LEFT);
        }

        return $this->precision > 0 ?
            str_pad(substr($result, -(($this->precision + 7) >> 3)), ($this->precision + 7) >> 3, chr(0), STR_PAD_LEFT) :
            $result;
    }

    /**
     * Converts a BigInteger to a hex string (eg. base-16)).
     *
     * Negative numbers are saved as positive numbers, unless $twos_compliment is set to true, at which point, they're
     * saved as two's compliment.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger('65');
     *
     *    echo $a->toHex(); // outputs '41'
     * ?>
     * </code>
     *
     * @param bool $twos_compliment
     * @return string
     * @access public
     * @internal Converts a base-2**26 number to base-2**8
     */
    function toHex($twos_compliment = false)
    {
        return bin2hex($this->toBytes($twos_compliment));
    }

    /**
     * Converts a BigInteger to a bit string (eg. base-2).
     *
     * Negative numbers are saved as positive numbers, unless $twos_compliment is set to true, at which point, they're
     * saved as two's compliment.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger('65');
     *
     *    echo $a->toBits(); // outputs '1000001'
     * ?>
     * </code>
     *
     * @param bool $twos_compliment
     * @return string
     * @access public
     * @internal Converts a base-2**26 number to base-2**2
     */
    function toBits($twos_compliment = false)
    {
        $hex = $this->toHex($twos_compliment);
        $bits = '';
        for ($i = strlen($hex) - 6, $start = strlen($hex) % 6; $i >= $start; $i-=6) {
            $bits = str_pad(decbin(hexdec(substr($hex, $i, 6))), 24, '0', STR_PAD_LEFT) . $bits;
        }
        if ($start) { // hexdec('') == 0
            $bits = str_pad(decbin(hexdec(substr($hex, 0, $start))), 8 * $start, '0', STR_PAD_LEFT) . $bits;
        }
        $result = $this->precision > 0 ? substr($bits, -$this->precision) : ltrim($bits, '0');

        if ($twos_compliment && $this->compare(new static()) > 0 && $this->precision <= 0) {
            return '0' . $result;
        }

        return $result;
    }

    /**
     * Converts a BigInteger to a base-10 number.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger('50');
     *
     *    echo $a->toString(); // outputs 50
     * ?>
     * </code>
     *
     * @return string
     * @access public
     * @internal Converts a base-2**26 number to base-10**7 (which is pretty much base-10)
     */
    function toString()
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                return gmp_strval($this->value);
            case self::MODE_BCMATH:
                if ($this->value === '0') {
                    return '0';
                }

                return ltrim($this->value, '0');
        }

        if (!count($this->value)) {
            return '0';
        }

        $temp = $this->copy();
        $temp->bitmask = false;
        $temp->is_negative = false;

        $divisor = new static();
        $divisor->value = array(self::$max10);
        $result = '';
        while (count($temp->value)) {
            list($temp, $mod) = $temp->divide($divisor);
            $result = str_pad(isset($mod->value[0]) ? $mod->value[0] : '', self::$max10Len, '0', STR_PAD_LEFT) . $result;
        }
        $result = ltrim($result, '0');
        if (empty($result)) {
            $result = '0';
        }

        if ($this->is_negative) {
            $result = '-' . $result;
        }

        return $result;
    }

    /**
     * Copy an object
     *
     * PHP5 passes objects by reference while PHP4 passes by value.  As such, we need a function to guarantee
     * that all objects are passed by value, when appropriate.  More information can be found here:
     *
     * {@link http://php.net/language.oop5.basic#51624}
     *
     * @access public
     * @see self::__clone()
     * @return \phpseclib\Math\BigInteger
     */
    function copy()
    {
        $temp = new static();
        $temp->value = $this->value;
        $temp->is_negative = $this->is_negative;
        $temp->precision = $this->precision;
        $temp->bitmask = $this->bitmask;
        return $temp;
    }

    /**
     *  __toString() magic method
     *
     * Will be called, automatically, if you're supporting just PHP5.  If you're supporting PHP4, you'll need to call
     * toString().
     *
     * @access public
     * @internal Implemented per a suggestion by Techie-Michael - thanks!
     */
    function __toString()
    {
        return $this->toString();
    }

    /**
     * __clone() magic method
     *
     * Although you can call BigInteger::__toString() directly in PHP5, you cannot call BigInteger::__clone() directly
     * in PHP5.  You can in PHP4 since it's not a magic method, but in PHP5, you have to call it by using the PHP5
     * only syntax of $y = clone $x.  As such, if you're trying to write an application that works on both PHP4 and
     * PHP5, call BigInteger::copy(), instead.
     *
     * @access public
     * @see self::copy()
     * @return \phpseclib\Math\BigInteger
     */
    function __clone()
    {
        return $this->copy();
    }

    /**
     *  __sleep() magic method
     *
     * Will be called, automatically, when serialize() is called on a BigInteger object.
     *
     * @see self::__wakeup()
     * @access public
     */
    function __sleep()
    {
        $this->hex = $this->toHex(true);
        $vars = array('hex');
        if ($this->precision > 0) {
            $vars[] = 'precision';
        }
        return $vars;
    }

    /**
     *  __wakeup() magic method
     *
     * Will be called, automatically, when unserialize() is called on a BigInteger object.
     *
     * @see self::__sleep()
     * @access public
     */
    function __wakeup()
    {
        $temp = new static($this->hex, -16);
        $this->value = $temp->value;
        $this->is_negative = $temp->is_negative;
        if ($this->precision > 0) {
            // recalculate $this->bitmask
            $this->setPrecision($this->precision);
        }
    }

    /**
     *  __debugInfo() magic method
     *
     * Will be called, automatically, when print_r() or var_dump() are called
     *
     * @access public
     */
    function __debugInfo()
    {
        $opts = array();
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                $engine = 'gmp';
                break;
            case self::MODE_BCMATH:
                $engine = 'bcmath';
                break;
            case self::MODE_INTERNAL:
                $engine = 'internal';
                $opts[] = PHP_INT_SIZE == 8 ? '64-bit' : '32-bit';
        }
        if (MATH_BIGINTEGER_MODE != self::MODE_GMP && defined('MATH_BIGINTEGER_OPENSSL_ENABLED')) {
            $opts[] = 'OpenSSL';
        }
        if (!empty($opts)) {
            $engine.= ' (' . implode('.', $opts) . ')';
        }
        return array(
            'value' => '0x' . $this->toHex(true),
            'engine' => $engine
        );
    }

    /**
     * Adds two BigIntegers.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger('10');
     *    $b = new \phpseclib\Math\BigInteger('20');
     *
     *    $c = $a->add($b);
     *
     *    echo $c->toString(); // outputs 30
     * ?>
     * </code>
     *
     * @param \phpseclib\Math\BigInteger $y
     * @return \phpseclib\Math\BigInteger
     * @access public
     * @internal Performs base-2**52 addition
     */
    function add($y)
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                $temp = new static();
                $temp->value = gmp_add($this->value, $y->value);

                return $this->_normalize($temp);
            case self::MODE_BCMATH:
                $temp = new static();
                $temp->value = bcadd($this->value, $y->value, 0);

                return $this->_normalize($temp);
        }

        $temp = $this->_add($this->value, $this->is_negative, $y->value, $y->is_negative);

        $result = new static();
        $result->value = $temp[self::VALUE];
        $result->is_negative = $temp[self::SIGN];

        return $this->_normalize($result);
    }

    /**
     * Performs addition.
     *
     * @param array $x_value
     * @param bool $x_negative
     * @param array $y_value
     * @param bool $y_negative
     * @return array
     * @access private
     */
    function _add($x_value, $x_negative, $y_value, $y_negative)
    {
        $x_size = count($x_value);
        $y_size = count($y_value);

        if ($x_size == 0) {
            return array(
                self::VALUE => $y_value,
                self::SIGN => $y_negative
            );
        } elseif ($y_size == 0) {
            return array(
                self::VALUE => $x_value,
                self::SIGN => $x_negative
            );
        }

        // subtract, if appropriate
        if ($x_negative != $y_negative) {
            if ($x_value == $y_value) {
                return array(
                    self::VALUE => array(),
                    self::SIGN => false
                );
            }

            $temp = $this->_subtract($x_value, false, $y_value, false);
            $temp[self::SIGN] = $this->_compare($x_value, false, $y_value, false) > 0 ?
                                          $x_negative : $y_negative;

            return $temp;
        }

        if ($x_size < $y_size) {
            $size = $x_size;
            $value = $y_value;
        } else {
            $size = $y_size;
            $value = $x_value;
        }

        $value[count($value)] = 0; // just in case the carry adds an extra digit

        $carry = 0;
        for ($i = 0, $j = 1; $j < $size; $i+=2, $j+=2) {
            $sum = $x_value[$j] * self::$baseFull + $x_value[$i] + $y_value[$j] * self::$baseFull + $y_value[$i] + $carry;
            $carry = $sum >= self::$maxDigit2; // eg. floor($sum / 2**52); only possible values (in any base) are 0 and 1
            $sum = $carry ? $sum - self::$maxDigit2 : $sum;

            $temp = self::$base === 26 ? intval($sum / 0x4000000) : ($sum >> 31);

            $value[$i] = (int) ($sum - self::$baseFull * $temp); // eg. a faster alternative to fmod($sum, 0x4000000)
            $value[$j] = $temp;
        }

        if ($j == $size) { // ie. if $y_size is odd
            $sum = $x_value[$i] + $y_value[$i] + $carry;
            $carry = $sum >= self::$baseFull;
            $value[$i] = $carry ? $sum - self::$baseFull : $sum;
            ++$i; // ie. let $i = $j since we've just done $value[$i]
        }

        if ($carry) {
            for (; $value[$i] == self::$maxDigit; ++$i) {
                $value[$i] = 0;
            }
            ++$value[$i];
        }

        return array(
            self::VALUE => $this->_trim($value),
            self::SIGN => $x_negative
        );
    }

    /**
     * Subtracts two BigIntegers.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger('10');
     *    $b = new \phpseclib\Math\BigInteger('20');
     *
     *    $c = $a->subtract($b);
     *
     *    echo $c->toString(); // outputs -10
     * ?>
     * </code>
     *
     * @param \phpseclib\Math\BigInteger $y
     * @return \phpseclib\Math\BigInteger
     * @access public
     * @internal Performs base-2**52 subtraction
     */
    function subtract($y)
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                $temp = new static();
                $temp->value = gmp_sub($this->value, $y->value);

                return $this->_normalize($temp);
            case self::MODE_BCMATH:
                $temp = new static();
                $temp->value = bcsub($this->value, $y->value, 0);

                return $this->_normalize($temp);
        }

        $temp = $this->_subtract($this->value, $this->is_negative, $y->value, $y->is_negative);

        $result = new static();
        $result->value = $temp[self::VALUE];
        $result->is_negative = $temp[self::SIGN];

        return $this->_normalize($result);
    }

    /**
     * Performs subtraction.
     *
     * @param array $x_value
     * @param bool $x_negative
     * @param array $y_value
     * @param bool $y_negative
     * @return array
     * @access private
     */
    function _subtract($x_value, $x_negative, $y_value, $y_negative)
    {
        $x_size = count($x_value);
        $y_size = count($y_value);

        if ($x_size == 0) {
            return array(
                self::VALUE => $y_value,
                self::SIGN => !$y_negative
            );
        } elseif ($y_size == 0) {
            return array(
                self::VALUE => $x_value,
                self::SIGN => $x_negative
            );
        }

        // add, if appropriate (ie. -$x - +$y or +$x - -$y)
        if ($x_negative != $y_negative) {
            $temp = $this->_add($x_value, false, $y_value, false);
            $temp[self::SIGN] = $x_negative;

            return $temp;
        }

        $diff = $this->_compare($x_value, $x_negative, $y_value, $y_negative);

        if (!$diff) {
            return array(
                self::VALUE => array(),
                self::SIGN => false
            );
        }

        // switch $x and $y around, if appropriate.
        if ((!$x_negative && $diff < 0) || ($x_negative && $diff > 0)) {
            $temp = $x_value;
            $x_value = $y_value;
            $y_value = $temp;

            $x_negative = !$x_negative;

            $x_size = count($x_value);
            $y_size = count($y_value);
        }

        // at this point, $x_value should be at least as big as - if not bigger than - $y_value

        $carry = 0;
        for ($i = 0, $j = 1; $j < $y_size; $i+=2, $j+=2) {
            $sum = $x_value[$j] * self::$baseFull + $x_value[$i] - $y_value[$j] * self::$baseFull - $y_value[$i] - $carry;
            $carry = $sum < 0; // eg. floor($sum / 2**52); only possible values (in any base) are 0 and 1
            $sum = $carry ? $sum + self::$maxDigit2 : $sum;

            $temp = self::$base === 26 ? intval($sum / 0x4000000) : ($sum >> 31);

            $x_value[$i] = (int) ($sum - self::$baseFull * $temp);
            $x_value[$j] = $temp;
        }

        if ($j == $y_size) { // ie. if $y_size is odd
            $sum = $x_value[$i] - $y_value[$i] - $carry;
            $carry = $sum < 0;
            $x_value[$i] = $carry ? $sum + self::$baseFull : $sum;
            ++$i;
        }

        if ($carry) {
            for (; !$x_value[$i]; ++$i) {
                $x_value[$i] = self::$maxDigit;
            }
            --$x_value[$i];
        }

        return array(
            self::VALUE => $this->_trim($x_value),
            self::SIGN => $x_negative
        );
    }

    /**
     * Multiplies two BigIntegers
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger('10');
     *    $b = new \phpseclib\Math\BigInteger('20');
     *
     *    $c = $a->multiply($b);
     *
     *    echo $c->toString(); // outputs 200
     * ?>
     * </code>
     *
     * @param \phpseclib\Math\BigInteger $x
     * @return \phpseclib\Math\BigInteger
     * @access public
     */
    function multiply($x)
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                $temp = new static();
                $temp->value = gmp_mul($this->value, $x->value);

                return $this->_normalize($temp);
            case self::MODE_BCMATH:
                $temp = new static();
                $temp->value = bcmul($this->value, $x->value, 0);

                return $this->_normalize($temp);
        }

        $temp = $this->_multiply($this->value, $this->is_negative, $x->value, $x->is_negative);

        $product = new static();
        $product->value = $temp[self::VALUE];
        $product->is_negative = $temp[self::SIGN];

        return $this->_normalize($product);
    }

    /**
     * Performs multiplication.
     *
     * @param array $x_value
     * @param bool $x_negative
     * @param array $y_value
     * @param bool $y_negative
     * @return array
     * @access private
     */
    function _multiply($x_value, $x_negative, $y_value, $y_negative)
    {
        //if ( $x_value == $y_value ) {
        //    return array(
        //        self::VALUE => $this->_square($x_value),
        //        self::SIGN => $x_sign != $y_value
        //    );
        //}

        $x_length = count($x_value);
        $y_length = count($y_value);

        if (!$x_length || !$y_length) { // a 0 is being multiplied
            return array(
                self::VALUE => array(),
                self::SIGN => false
            );
        }

        return array(
            self::VALUE => min($x_length, $y_length) < 2 * self::KARATSUBA_CUTOFF ?
                $this->_trim($this->_regularMultiply($x_value, $y_value)) :
                $this->_trim($this->_karatsuba($x_value, $y_value)),
            self::SIGN => $x_negative != $y_negative
        );
    }

    /**
     * Performs long multiplication on two BigIntegers
     *
     * Modeled after 'multiply' in MutableBigInteger.java.
     *
     * @param array $x_value
     * @param array $y_value
     * @return array
     * @access private
     */
    function _regularMultiply($x_value, $y_value)
    {
        $x_length = count($x_value);
        $y_length = count($y_value);

        if (!$x_length || !$y_length) { // a 0 is being multiplied
            return array();
        }

        if ($x_length < $y_length) {
            $temp = $x_value;
            $x_value = $y_value;
            $y_value = $temp;

            $x_length = count($x_value);
            $y_length = count($y_value);
        }

        $product_value = $this->_array_repeat(0, $x_length + $y_length);

        // the following for loop could be removed if the for loop following it
        // (the one with nested for loops) initially set $i to 0, but
        // doing so would also make the result in one set of unnecessary adds,
        // since on the outermost loops first pass, $product->value[$k] is going
        // to always be 0

        $carry = 0;

        for ($j = 0; $j < $x_length; ++$j) { // ie. $i = 0
            $temp = $x_value[$j] * $y_value[0] + $carry; // $product_value[$k] == 0
            $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
            $product_value[$j] = (int) ($temp - self::$baseFull * $carry);
        }

        $product_value[$j] = $carry;

        // the above for loop is what the previous comment was talking about.  the
        // following for loop is the "one with nested for loops"
        for ($i = 1; $i < $y_length; ++$i) {
            $carry = 0;

            for ($j = 0, $k = $i; $j < $x_length; ++$j, ++$k) {
                $temp = $product_value[$k] + $x_value[$j] * $y_value[$i] + $carry;
                $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
                $product_value[$k] = (int) ($temp - self::$baseFull * $carry);
            }

            $product_value[$k] = $carry;
        }

        return $product_value;
    }

    /**
     * Performs Karatsuba multiplication on two BigIntegers
     *
     * See {@link http://en.wikipedia.org/wiki/Karatsuba_algorithm Karatsuba algorithm} and
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=120 MPM 5.2.3}.
     *
     * @param array $x_value
     * @param array $y_value
     * @return array
     * @access private
     */
    function _karatsuba($x_value, $y_value)
    {
        $m = min(count($x_value) >> 1, count($y_value) >> 1);

        if ($m < self::KARATSUBA_CUTOFF) {
            return $this->_regularMultiply($x_value, $y_value);
        }

        $x1 = array_slice($x_value, $m);
        $x0 = array_slice($x_value, 0, $m);
        $y1 = array_slice($y_value, $m);
        $y0 = array_slice($y_value, 0, $m);

        $z2 = $this->_karatsuba($x1, $y1);
        $z0 = $this->_karatsuba($x0, $y0);

        $z1 = $this->_add($x1, false, $x0, false);
        $temp = $this->_add($y1, false, $y0, false);
        $z1 = $this->_karatsuba($z1[self::VALUE], $temp[self::VALUE]);
        $temp = $this->_add($z2, false, $z0, false);
        $z1 = $this->_subtract($z1, false, $temp[self::VALUE], false);

        $z2 = array_merge(array_fill(0, 2 * $m, 0), $z2);
        $z1[self::VALUE] = array_merge(array_fill(0, $m, 0), $z1[self::VALUE]);

        $xy = $this->_add($z2, false, $z1[self::VALUE], $z1[self::SIGN]);
        $xy = $this->_add($xy[self::VALUE], $xy[self::SIGN], $z0, false);

        return $xy[self::VALUE];
    }

    /**
     * Performs squaring
     *
     * @param array $x
     * @return array
     * @access private
     */
    function _square($x = false)
    {
        return count($x) < 2 * self::KARATSUBA_CUTOFF ?
            $this->_trim($this->_baseSquare($x)) :
            $this->_trim($this->_karatsubaSquare($x));
    }

    /**
     * Performs traditional squaring on two BigIntegers
     *
     * Squaring can be done faster than multiplying a number by itself can be.  See
     * {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=7 HAC 14.2.4} /
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=141 MPM 5.3} for more information.
     *
     * @param array $value
     * @return array
     * @access private
     */
    function _baseSquare($value)
    {
        if (empty($value)) {
            return array();
        }
        $square_value = $this->_array_repeat(0, 2 * count($value));

        for ($i = 0, $max_index = count($value) - 1; $i <= $max_index; ++$i) {
            $i2 = $i << 1;

            $temp = $square_value[$i2] + $value[$i] * $value[$i];
            $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
            $square_value[$i2] = (int) ($temp - self::$baseFull * $carry);

            // note how we start from $i+1 instead of 0 as we do in multiplication.
            for ($j = $i + 1, $k = $i2 + 1; $j <= $max_index; ++$j, ++$k) {
                $temp = $square_value[$k] + 2 * $value[$j] * $value[$i] + $carry;
                $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
                $square_value[$k] = (int) ($temp - self::$baseFull * $carry);
            }

            // the following line can yield values larger 2**15.  at this point, PHP should switch
            // over to floats.
            $square_value[$i + $max_index + 1] = $carry;
        }

        return $square_value;
    }

    /**
     * Performs Karatsuba "squaring" on two BigIntegers
     *
     * See {@link http://en.wikipedia.org/wiki/Karatsuba_algorithm Karatsuba algorithm} and
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=151 MPM 5.3.4}.
     *
     * @param array $value
     * @return array
     * @access private
     */
    function _karatsubaSquare($value)
    {
        $m = count($value) >> 1;

        if ($m < self::KARATSUBA_CUTOFF) {
            return $this->_baseSquare($value);
        }

        $x1 = array_slice($value, $m);
        $x0 = array_slice($value, 0, $m);

        $z2 = $this->_karatsubaSquare($x1);
        $z0 = $this->_karatsubaSquare($x0);

        $z1 = $this->_add($x1, false, $x0, false);
        $z1 = $this->_karatsubaSquare($z1[self::VALUE]);
        $temp = $this->_add($z2, false, $z0, false);
        $z1 = $this->_subtract($z1, false, $temp[self::VALUE], false);

        $z2 = array_merge(array_fill(0, 2 * $m, 0), $z2);
        $z1[self::VALUE] = array_merge(array_fill(0, $m, 0), $z1[self::VALUE]);

        $xx = $this->_add($z2, false, $z1[self::VALUE], $z1[self::SIGN]);
        $xx = $this->_add($xx[self::VALUE], $xx[self::SIGN], $z0, false);

        return $xx[self::VALUE];
    }

    /**
     * Divides two BigIntegers.
     *
     * Returns an array whose first element contains the quotient and whose second element contains the
     * "common residue".  If the remainder would be positive, the "common residue" and the remainder are the
     * same.  If the remainder would be negative, the "common residue" is equal to the sum of the remainder
     * and the divisor (basically, the "common residue" is the first positive modulo).
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger('10');
     *    $b = new \phpseclib\Math\BigInteger('20');
     *
     *    list($quotient, $remainder) = $a->divide($b);
     *
     *    echo $quotient->toString(); // outputs 0
     *    echo "\r\n";
     *    echo $remainder->toString(); // outputs 10
     * ?>
     * </code>
     *
     * @param \phpseclib\Math\BigInteger $y
     * @return array
     * @access public
     * @internal This function is based off of {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=9 HAC 14.20}.
     */
    function divide($y)
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                $quotient = new static();
                $remainder = new static();

                list($quotient->value, $remainder->value) = gmp_div_qr($this->value, $y->value);

                if (gmp_sign($remainder->value) < 0) {
                    $remainder->value = gmp_add($remainder->value, gmp_abs($y->value));
                }

                return array($this->_normalize($quotient), $this->_normalize($remainder));
            case self::MODE_BCMATH:
                $quotient = new static();
                $remainder = new static();

                $quotient->value = bcdiv($this->value, $y->value, 0);
                $remainder->value = bcmod($this->value, $y->value);

                if ($remainder->value[0] == '-') {
                    $remainder->value = bcadd($remainder->value, $y->value[0] == '-' ? substr($y->value, 1) : $y->value, 0);
                }

                return array($this->_normalize($quotient), $this->_normalize($remainder));
        }

        if (count($y->value) == 1) {
            list($q, $r) = $this->_divide_digit($this->value, $y->value[0]);
            $quotient = new static();
            $remainder = new static();
            $quotient->value = $q;
            $remainder->value = array($r);
            $quotient->is_negative = $this->is_negative != $y->is_negative;
            return array($this->_normalize($quotient), $this->_normalize($remainder));
        }

        static $zero;
        if (!isset($zero)) {
            $zero = new static();
        }

        $x = $this->copy();
        $y = $y->copy();

        $x_sign = $x->is_negative;
        $y_sign = $y->is_negative;

        $x->is_negative = $y->is_negative = false;

        $diff = $x->compare($y);

        if (!$diff) {
            $temp = new static();
            $temp->value = array(1);
            $temp->is_negative = $x_sign != $y_sign;
            return array($this->_normalize($temp), $this->_normalize(new static()));
        }

        if ($diff < 0) {
            // if $x is negative, "add" $y.
            if ($x_sign) {
                $x = $y->subtract($x);
            }
            return array($this->_normalize(new static()), $this->_normalize($x));
        }

        // normalize $x and $y as described in HAC 14.23 / 14.24
        $msb = $y->value[count($y->value) - 1];
        for ($shift = 0; !($msb & self::$msb); ++$shift) {
            $msb <<= 1;
        }
        $x->_lshift($shift);
        $y->_lshift($shift);
        $y_value = &$y->value;

        $x_max = count($x->value) - 1;
        $y_max = count($y->value) - 1;

        $quotient = new static();
        $quotient_value = &$quotient->value;
        $quotient_value = $this->_array_repeat(0, $x_max - $y_max + 1);

        static $temp, $lhs, $rhs;
        if (!isset($temp)) {
            $temp = new static();
            $lhs =  new static();
            $rhs =  new static();
        }
        $temp_value = &$temp->value;
        $rhs_value =  &$rhs->value;

        // $temp = $y << ($x_max - $y_max-1) in base 2**26
        $temp_value = array_merge($this->_array_repeat(0, $x_max - $y_max), $y_value);

        while ($x->compare($temp) >= 0) {
            // calculate the "common residue"
            ++$quotient_value[$x_max - $y_max];
            $x = $x->subtract($temp);
            $x_max = count($x->value) - 1;
        }

        for ($i = $x_max; $i >= $y_max + 1; --$i) {
            $x_value = &$x->value;
            $x_window = array(
                isset($x_value[$i]) ? $x_value[$i] : 0,
                isset($x_value[$i - 1]) ? $x_value[$i - 1] : 0,
                isset($x_value[$i - 2]) ? $x_value[$i - 2] : 0
            );
            $y_window = array(
                $y_value[$y_max],
                ($y_max > 0) ? $y_value[$y_max - 1] : 0
            );

            $q_index = $i - $y_max - 1;
            if ($x_window[0] == $y_window[0]) {
                $quotient_value[$q_index] = self::$maxDigit;
            } else {
                $quotient_value[$q_index] = $this->_safe_divide(
                    $x_window[0] * self::$baseFull + $x_window[1],
                    $y_window[0]
                );
            }

            $temp_value = array($y_window[1], $y_window[0]);

            $lhs->value = array($quotient_value[$q_index]);
            $lhs = $lhs->multiply($temp);

            $rhs_value = array($x_window[2], $x_window[1], $x_window[0]);

            while ($lhs->compare($rhs) > 0) {
                --$quotient_value[$q_index];

                $lhs->value = array($quotient_value[$q_index]);
                $lhs = $lhs->multiply($temp);
            }

            $adjust = $this->_array_repeat(0, $q_index);
            $temp_value = array($quotient_value[$q_index]);
            $temp = $temp->multiply($y);
            $temp_value = &$temp->value;
            if (count($temp_value)) {
                $temp_value = array_merge($adjust, $temp_value);
            }

            $x = $x->subtract($temp);

            if ($x->compare($zero) < 0) {
                $temp_value = array_merge($adjust, $y_value);
                $x = $x->add($temp);

                --$quotient_value[$q_index];
            }

            $x_max = count($x_value) - 1;
        }

        // unnormalize the remainder
        $x->_rshift($shift);

        $quotient->is_negative = $x_sign != $y_sign;

        // calculate the "common residue", if appropriate
        if ($x_sign) {
            $y->_rshift($shift);
            $x = $y->subtract($x);
        }

        return array($this->_normalize($quotient), $this->_normalize($x));
    }

    /**
     * Divides a BigInteger by a regular integer
     *
     * abc / x = a00 / x + b0 / x + c / x
     *
     * @param array $dividend
     * @param array $divisor
     * @return array
     * @access private
     */
    function _divide_digit($dividend, $divisor)
    {
        $carry = 0;
        $result = array();

        for ($i = count($dividend) - 1; $i >= 0; --$i) {
            $temp = self::$baseFull * $carry + $dividend[$i];
            $result[$i] = $this->_safe_divide($temp, $divisor);
            $carry = (int) ($temp - $divisor * $result[$i]);
        }

        return array($result, $carry);
    }

    /**
     * Performs modular exponentiation.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger('10');
     *    $b = new \phpseclib\Math\BigInteger('20');
     *    $c = new \phpseclib\Math\BigInteger('30');
     *
     *    $c = $a->modPow($b, $c);
     *
     *    echo $c->toString(); // outputs 10
     * ?>
     * </code>
     *
     * @param \phpseclib\Math\BigInteger $e
     * @param \phpseclib\Math\BigInteger $n
     * @return \phpseclib\Math\BigInteger
     * @access public
     * @internal The most naive approach to modular exponentiation has very unreasonable requirements, and
     *    and although the approach involving repeated squaring does vastly better, it, too, is impractical
     *    for our purposes.  The reason being that division - by far the most complicated and time-consuming
     *    of the basic operations (eg. +,-,*,/) - occurs multiple times within it.
     *
     *    Modular reductions resolve this issue.  Although an individual modular reduction takes more time
     *    then an individual division, when performed in succession (with the same modulo), they're a lot faster.
     *
     *    The two most commonly used modular reductions are Barrett and Montgomery reduction.  Montgomery reduction,
     *    although faster, only works when the gcd of the modulo and of the base being used is 1.  In RSA, when the
     *    base is a power of two, the modulo - a product of two primes - is always going to have a gcd of 1 (because
     *    the product of two odd numbers is odd), but what about when RSA isn't used?
     *
     *    In contrast, Barrett reduction has no such constraint.  As such, some bigint implementations perform a
     *    Barrett reduction after every operation in the modpow function.  Others perform Barrett reductions when the
     *    modulo is even and Montgomery reductions when the modulo is odd.  BigInteger.java's modPow method, however,
     *    uses a trick involving the Chinese Remainder Theorem to factor the even modulo into two numbers - one odd and
     *    the other, a power of two - and recombine them, later.  This is the method that this modPow function uses.
     *    {@link http://islab.oregonstate.edu/papers/j34monex.pdf Montgomery Reduction with Even Modulus} elaborates.
     */
    function modPow($e, $n)
    {
        $n = $this->bitmask !== false && $this->bitmask->compare($n) < 0 ? $this->bitmask : $n->abs();

        if ($e->compare(new static()) < 0) {
            $e = $e->abs();

            $temp = $this->modInverse($n);
            if ($temp === false) {
                return false;
            }

            return $this->_normalize($temp->modPow($e, $n));
        }

        if (MATH_BIGINTEGER_MODE == self::MODE_GMP) {
            $temp = new static();
            $temp->value = gmp_powm($this->value, $e->value, $n->value);

            return $this->_normalize($temp);
        }

        if ($this->compare(new static()) < 0 || $this->compare($n) > 0) {
            list(, $temp) = $this->divide($n);
            return $temp->modPow($e, $n);
        }

        if (defined('MATH_BIGINTEGER_OPENSSL_ENABLED')) {
            $components = array(
                'modulus' => $n->toBytes(true),
                'publicExponent' => $e->toBytes(true)
            );

            $components = array(
                'modulus' => pack('Ca*a*', 2, $this->_encodeASN1Length(strlen($components['modulus'])), $components['modulus']),
                'publicExponent' => pack('Ca*a*', 2, $this->_encodeASN1Length(strlen($components['publicExponent'])), $components['publicExponent'])
            );

            $RSAPublicKey = pack(
                'Ca*a*a*',
                48,
                $this->_encodeASN1Length(strlen($components['modulus']) + strlen($components['publicExponent'])),
                $components['modulus'],
                $components['publicExponent']
            );

            $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
            $RSAPublicKey = chr(0) . $RSAPublicKey;
            $RSAPublicKey = chr(3) . $this->_encodeASN1Length(strlen($RSAPublicKey)) . $RSAPublicKey;

            $encapsulated = pack(
                'Ca*a*',
                48,
                $this->_encodeASN1Length(strlen($rsaOID . $RSAPublicKey)),
                $rsaOID . $RSAPublicKey
            );

            $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
                             chunk_split(base64_encode($encapsulated)) .
                             '-----END PUBLIC KEY-----';

            $plaintext = str_pad($this->toBytes(), strlen($n->toBytes(true)) - 1, "\0", STR_PAD_LEFT);

            if (openssl_public_encrypt($plaintext, $result, $RSAPublicKey, OPENSSL_NO_PADDING)) {
                return new static($result, 256);
            }
        }

        if (MATH_BIGINTEGER_MODE == self::MODE_BCMATH) {
            $temp = new static();
            $temp->value = bcpowmod($this->value, $e->value, $n->value, 0);

            return $this->_normalize($temp);
        }

        if (empty($e->value)) {
            $temp = new static();
            $temp->value = array(1);
            return $this->_normalize($temp);
        }

        if ($e->value == array(1)) {
            list(, $temp) = $this->divide($n);
            return $this->_normalize($temp);
        }

        if ($e->value == array(2)) {
            $temp = new static();
            $temp->value = $this->_square($this->value);
            list(, $temp) = $temp->divide($n);
            return $this->_normalize($temp);
        }

        return $this->_normalize($this->_slidingWindow($e, $n, self::BARRETT));

        // the following code, although not callable, can be run independently of the above code
        // although the above code performed better in my benchmarks the following could might
        // perform better under different circumstances. in lieu of deleting it it's just been
        // made uncallable

        // is the modulo odd?
        if ($n->value[0] & 1) {
            return $this->_normalize($this->_slidingWindow($e, $n, self::MONTGOMERY));
        }
        // if it's not, it's even

        // find the lowest set bit (eg. the max pow of 2 that divides $n)
        for ($i = 0; $i < count($n->value); ++$i) {
            if ($n->value[$i]) {
                $temp = decbin($n->value[$i]);
                $j = strlen($temp) - strrpos($temp, '1') - 1;
                $j+= 26 * $i;
                break;
            }
        }
        // at this point, 2^$j * $n/(2^$j) == $n

        $mod1 = $n->copy();
        $mod1->_rshift($j);
        $mod2 = new static();
        $mod2->value = array(1);
        $mod2->_lshift($j);

        $part1 = ($mod1->value != array(1)) ? $this->_slidingWindow($e, $mod1, self::MONTGOMERY) : new static();
        $part2 = $this->_slidingWindow($e, $mod2, self::POWEROF2);

        $y1 = $mod2->modInverse($mod1);
        $y2 = $mod1->modInverse($mod2);

        $result = $part1->multiply($mod2);
        $result = $result->multiply($y1);

        $temp = $part2->multiply($mod1);
        $temp = $temp->multiply($y2);

        $result = $result->add($temp);
        list(, $result) = $result->divide($n);

        return $this->_normalize($result);
    }

    /**
     * Performs modular exponentiation.
     *
     * Alias for modPow().
     *
     * @param \phpseclib\Math\BigInteger $e
     * @param \phpseclib\Math\BigInteger $n
     * @return \phpseclib\Math\BigInteger
     * @access public
     */
    function powMod($e, $n)
    {
        return $this->modPow($e, $n);
    }

    /**
     * Sliding Window k-ary Modular Exponentiation
     *
     * Based on {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=27 HAC 14.85} /
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=210 MPM 7.7}.  In a departure from those algorithims,
     * however, this function performs a modular reduction after every multiplication and squaring operation.
     * As such, this function has the same preconditions that the reductions being used do.
     *
     * @param \phpseclib\Math\BigInteger $e
     * @param \phpseclib\Math\BigInteger $n
     * @param int $mode
     * @return \phpseclib\Math\BigInteger
     * @access private
     */
    function _slidingWindow($e, $n, $mode)
    {
        static $window_ranges = array(7, 25, 81, 241, 673, 1793); // from BigInteger.java's oddModPow function
        //static $window_ranges = array(0, 7, 36, 140, 450, 1303, 3529); // from MPM 7.3.1

        $e_value = $e->value;
        $e_length = count($e_value) - 1;
        $e_bits = decbin($e_value[$e_length]);
        for ($i = $e_length - 1; $i >= 0; --$i) {
            $e_bits.= str_pad(decbin($e_value[$i]), self::$base, '0', STR_PAD_LEFT);
        }

        $e_length = strlen($e_bits);

        // calculate the appropriate window size.
        // $window_size == 3 if $window_ranges is between 25 and 81, for example.
        for ($i = 0, $window_size = 1; $i < count($window_ranges) && $e_length > $window_ranges[$i]; ++$window_size, ++$i) {
        }

        $n_value = $n->value;

        // precompute $this^0 through $this^$window_size
        $powers = array();
        $powers[1] = $this->_prepareReduce($this->value, $n_value, $mode);
        $powers[2] = $this->_squareReduce($powers[1], $n_value, $mode);

        // we do every other number since substr($e_bits, $i, $j+1) (see below) is supposed to end
        // in a 1.  ie. it's supposed to be odd.
        $temp = 1 << ($window_size - 1);
        for ($i = 1; $i < $temp; ++$i) {
            $i2 = $i << 1;
            $powers[$i2 + 1] = $this->_multiplyReduce($powers[$i2 - 1], $powers[2], $n_value, $mode);
        }

        $result = array(1);
        $result = $this->_prepareReduce($result, $n_value, $mode);

        for ($i = 0; $i < $e_length;) {
            if (!$e_bits[$i]) {
                $result = $this->_squareReduce($result, $n_value, $mode);
                ++$i;
            } else {
                for ($j = $window_size - 1; $j > 0; --$j) {
                    if (!empty($e_bits[$i + $j])) {
                        break;
                    }
                }

                // eg. the length of substr($e_bits, $i, $j + 1)
                for ($k = 0; $k <= $j; ++$k) {
                    $result = $this->_squareReduce($result, $n_value, $mode);
                }

                $result = $this->_multiplyReduce($result, $powers[bindec(substr($e_bits, $i, $j + 1))], $n_value, $mode);

                $i += $j + 1;
            }
        }

        $temp = new static();
        $temp->value = $this->_reduce($result, $n_value, $mode);

        return $temp;
    }

    /**
     * Modular reduction
     *
     * For most $modes this will return the remainder.
     *
     * @see self::_slidingWindow()
     * @access private
     * @param array $x
     * @param array $n
     * @param int $mode
     * @return array
     */
    function _reduce($x, $n, $mode)
    {
        switch ($mode) {
            case self::MONTGOMERY:
                return $this->_montgomery($x, $n);
            case self::BARRETT:
                return $this->_barrett($x, $n);
            case self::POWEROF2:
                $lhs = new static();
                $lhs->value = $x;
                $rhs = new static();
                $rhs->value = $n;
                return $x->_mod2($n);
            case self::CLASSIC:
                $lhs = new static();
                $lhs->value = $x;
                $rhs = new static();
                $rhs->value = $n;
                list(, $temp) = $lhs->divide($rhs);
                return $temp->value;
            case self::NONE:
                return $x;
            default:
                // an invalid $mode was provided
        }
    }

    /**
     * Modular reduction preperation
     *
     * @see self::_slidingWindow()
     * @access private
     * @param array $x
     * @param array $n
     * @param int $mode
     * @return array
     */
    function _prepareReduce($x, $n, $mode)
    {
        if ($mode == self::MONTGOMERY) {
            return $this->_prepMontgomery($x, $n);
        }
        return $this->_reduce($x, $n, $mode);
    }

    /**
     * Modular multiply
     *
     * @see self::_slidingWindow()
     * @access private
     * @param array $x
     * @param array $y
     * @param array $n
     * @param int $mode
     * @return array
     */
    function _multiplyReduce($x, $y, $n, $mode)
    {
        if ($mode == self::MONTGOMERY) {
            return $this->_montgomeryMultiply($x, $y, $n);
        }
        $temp = $this->_multiply($x, false, $y, false);
        return $this->_reduce($temp[self::VALUE], $n, $mode);
    }

    /**
     * Modular square
     *
     * @see self::_slidingWindow()
     * @access private
     * @param array $x
     * @param array $n
     * @param int $mode
     * @return array
     */
    function _squareReduce($x, $n, $mode)
    {
        if ($mode == self::MONTGOMERY) {
            return $this->_montgomeryMultiply($x, $x, $n);
        }
        return $this->_reduce($this->_square($x), $n, $mode);
    }

    /**
     * Modulos for Powers of Two
     *
     * Calculates $x%$n, where $n = 2**$e, for some $e.  Since this is basically the same as doing $x & ($n-1),
     * we'll just use this function as a wrapper for doing that.
     *
     * @see self::_slidingWindow()
     * @access private
     * @param \phpseclib\Math\BigInteger $n
     * @return \phpseclib\Math\BigInteger
     */
    function _mod2($n)
    {
        $temp = new static();
        $temp->value = array(1);
        return $this->bitwise_and($n->subtract($temp));
    }

    /**
     * Barrett Modular Reduction
     *
     * See {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=14 HAC 14.3.3} /
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=165 MPM 6.2.5} for more information.  Modified slightly,
     * so as not to require negative numbers (initially, this script didn't support negative numbers).
     *
     * Employs "folding", as described at
     * {@link http://www.cosic.esat.kuleuven.be/publications/thesis-149.pdf#page=66 thesis-149.pdf#page=66}.  To quote from
     * it, "the idea [behind folding] is to find a value x' such that x (mod m) = x' (mod m), with x' being smaller than x."
     *
     * Unfortunately, the "Barrett Reduction with Folding" algorithm described in thesis-149.pdf is not, as written, all that
     * usable on account of (1) its not using reasonable radix points as discussed in
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=162 MPM 6.2.2} and (2) the fact that, even with reasonable
     * radix points, it only works when there are an even number of digits in the denominator.  The reason for (2) is that
     * (x >> 1) + (x >> 1) != x / 2 + x / 2.  If x is even, they're the same, but if x is odd, they're not.  See the in-line
     * comments for details.
     *
     * @see self::_slidingWindow()
     * @access private
     * @param array $n
     * @param array $m
     * @return array
     */
    function _barrett($n, $m)
    {
        static $cache = array(
            self::VARIABLE => array(),
            self::DATA => array()
        );

        $m_length = count($m);

        // if ($this->_compare($n, $this->_square($m)) >= 0) {
        if (count($n) > 2 * $m_length) {
            $lhs = new static();
            $rhs = new static();
            $lhs->value = $n;
            $rhs->value = $m;
            list(, $temp) = $lhs->divide($rhs);
            return $temp->value;
        }

        // if (m.length >> 1) + 2 <= m.length then m is too small and n can't be reduced
        if ($m_length < 5) {
            return $this->_regularBarrett($n, $m);
        }

        // n = 2 * m.length

        if (($key = array_search($m, $cache[self::VARIABLE])) === false) {
            $key = count($cache[self::VARIABLE]);
            $cache[self::VARIABLE][] = $m;

            $lhs = new static();
            $lhs_value = &$lhs->value;
            $lhs_value = $this->_array_repeat(0, $m_length + ($m_length >> 1));
            $lhs_value[] = 1;
            $rhs = new static();
            $rhs->value = $m;

            list($u, $m1) = $lhs->divide($rhs);
            $u = $u->value;
            $m1 = $m1->value;

            $cache[self::DATA][] = array(
                'u' => $u, // m.length >> 1 (technically (m.length >> 1) + 1)
                'm1'=> $m1 // m.length
            );
        } else {
            extract($cache[self::DATA][$key]);
        }

        $cutoff = $m_length + ($m_length >> 1);
        $lsd = array_slice($n, 0, $cutoff); // m.length + (m.length >> 1)
        $msd = array_slice($n, $cutoff);    // m.length >> 1
        $lsd = $this->_trim($lsd);
        $temp = $this->_multiply($msd, false, $m1, false);
        $n = $this->_add($lsd, false, $temp[self::VALUE], false); // m.length + (m.length >> 1) + 1

        if ($m_length & 1) {
            return $this->_regularBarrett($n[self::VALUE], $m);
        }

        // (m.length + (m.length >> 1) + 1) - (m.length - 1) == (m.length >> 1) + 2
        $temp = array_slice($n[self::VALUE], $m_length - 1);
        // if even: ((m.length >> 1) + 2) + (m.length >> 1) == m.length + 2
        // if odd:  ((m.length >> 1) + 2) + (m.length >> 1) == (m.length - 1) + 2 == m.length + 1
        $temp = $this->_multiply($temp, false, $u, false);
        // if even: (m.length + 2) - ((m.length >> 1) + 1) = m.length - (m.length >> 1) + 1
        // if odd:  (m.length + 1) - ((m.length >> 1) + 1) = m.length - (m.length >> 1)
        $temp = array_slice($temp[self::VALUE], ($m_length >> 1) + 1);
        // if even: (m.length - (m.length >> 1) + 1) + m.length = 2 * m.length - (m.length >> 1) + 1
        // if odd:  (m.length - (m.length >> 1)) + m.length     = 2 * m.length - (m.length >> 1)
        $temp = $this->_multiply($temp, false, $m, false);

        // at this point, if m had an odd number of digits, we'd be subtracting a 2 * m.length - (m.length >> 1) digit
        // number from a m.length + (m.length >> 1) + 1 digit number.  ie. there'd be an extra digit and the while loop
        // following this comment would loop a lot (hence our calling _regularBarrett() in that situation).

        $result = $this->_subtract($n[self::VALUE], false, $temp[self::VALUE], false);

        while ($this->_compare($result[self::VALUE], $result[self::SIGN], $m, false) >= 0) {
            $result = $this->_subtract($result[self::VALUE], $result[self::SIGN], $m, false);
        }

        return $result[self::VALUE];
    }

    /**
     * (Regular) Barrett Modular Reduction
     *
     * For numbers with more than four digits BigInteger::_barrett() is faster.  The difference between that and this
     * is that this function does not fold the denominator into a smaller form.
     *
     * @see self::_slidingWindow()
     * @access private
     * @param array $x
     * @param array $n
     * @return array
     */
    function _regularBarrett($x, $n)
    {
        static $cache = array(
            self::VARIABLE => array(),
            self::DATA => array()
        );

        $n_length = count($n);

        if (count($x) > 2 * $n_length) {
            $lhs = new static();
            $rhs = new static();
            $lhs->value = $x;
            $rhs->value = $n;
            list(, $temp) = $lhs->divide($rhs);
            return $temp->value;
        }

        if (($key = array_search($n, $cache[self::VARIABLE])) === false) {
            $key = count($cache[self::VARIABLE]);
            $cache[self::VARIABLE][] = $n;
            $lhs = new static();
            $lhs_value = &$lhs->value;
            $lhs_value = $this->_array_repeat(0, 2 * $n_length);
            $lhs_value[] = 1;
            $rhs = new static();
            $rhs->value = $n;
            list($temp, ) = $lhs->divide($rhs); // m.length
            $cache[self::DATA][] = $temp->value;
        }

        // 2 * m.length - (m.length - 1) = m.length + 1
        $temp = array_slice($x, $n_length - 1);
        // (m.length + 1) + m.length = 2 * m.length + 1
        $temp = $this->_multiply($temp, false, $cache[self::DATA][$key], false);
        // (2 * m.length + 1) - (m.length - 1) = m.length + 2
        $temp = array_slice($temp[self::VALUE], $n_length + 1);

        // m.length + 1
        $result = array_slice($x, 0, $n_length + 1);
        // m.length + 1
        $temp = $this->_multiplyLower($temp, false, $n, false, $n_length + 1);
        // $temp == array_slice($temp->_multiply($temp, false, $n, false)->value, 0, $n_length + 1)

        if ($this->_compare($result, false, $temp[self::VALUE], $temp[self::SIGN]) < 0) {
            $corrector_value = $this->_array_repeat(0, $n_length + 1);
            $corrector_value[count($corrector_value)] = 1;
            $result = $this->_add($result, false, $corrector_value, false);
            $result = $result[self::VALUE];
        }

        // at this point, we're subtracting a number with m.length + 1 digits from another number with m.length + 1 digits
        $result = $this->_subtract($result, false, $temp[self::VALUE], $temp[self::SIGN]);
        while ($this->_compare($result[self::VALUE], $result[self::SIGN], $n, false) > 0) {
            $result = $this->_subtract($result[self::VALUE], $result[self::SIGN], $n, false);
        }

        return $result[self::VALUE];
    }

    /**
     * Performs long multiplication up to $stop digits
     *
     * If you're going to be doing array_slice($product->value, 0, $stop), some cycles can be saved.
     *
     * @see self::_regularBarrett()
     * @param array $x_value
     * @param bool $x_negative
     * @param array $y_value
     * @param bool $y_negative
     * @param int $stop
     * @return array
     * @access private
     */
    function _multiplyLower($x_value, $x_negative, $y_value, $y_negative, $stop)
    {
        $x_length = count($x_value);
        $y_length = count($y_value);

        if (!$x_length || !$y_length) { // a 0 is being multiplied
            return array(
                self::VALUE => array(),
                self::SIGN => false
            );
        }

        if ($x_length < $y_length) {
            $temp = $x_value;
            $x_value = $y_value;
            $y_value = $temp;

            $x_length = count($x_value);
            $y_length = count($y_value);
        }

        $product_value = $this->_array_repeat(0, $x_length + $y_length);

        // the following for loop could be removed if the for loop following it
        // (the one with nested for loops) initially set $i to 0, but
        // doing so would also make the result in one set of unnecessary adds,
        // since on the outermost loops first pass, $product->value[$k] is going
        // to always be 0

        $carry = 0;

        for ($j = 0; $j < $x_length; ++$j) { // ie. $i = 0, $k = $i
            $temp = $x_value[$j] * $y_value[0] + $carry; // $product_value[$k] == 0
            $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
            $product_value[$j] = (int) ($temp - self::$baseFull * $carry);
        }

        if ($j < $stop) {
            $product_value[$j] = $carry;
        }

        // the above for loop is what the previous comment was talking about.  the
        // following for loop is the "one with nested for loops"

        for ($i = 1; $i < $y_length; ++$i) {
            $carry = 0;

            for ($j = 0, $k = $i; $j < $x_length && $k < $stop; ++$j, ++$k) {
                $temp = $product_value[$k] + $x_value[$j] * $y_value[$i] + $carry;
                $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
                $product_value[$k] = (int) ($temp - self::$baseFull * $carry);
            }

            if ($k < $stop) {
                $product_value[$k] = $carry;
            }
        }

        return array(
            self::VALUE => $this->_trim($product_value),
            self::SIGN => $x_negative != $y_negative
        );
    }

    /**
     * Montgomery Modular Reduction
     *
     * ($x->_prepMontgomery($n))->_montgomery($n) yields $x % $n.
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=170 MPM 6.3} provides insights on how this can be
     * improved upon (basically, by using the comba method).  gcd($n, 2) must be equal to one for this function
     * to work correctly.
     *
     * @see self::_prepMontgomery()
     * @see self::_slidingWindow()
     * @access private
     * @param array $x
     * @param array $n
     * @return array
     */
    function _montgomery($x, $n)
    {
        static $cache = array(
            self::VARIABLE => array(),
            self::DATA => array()
        );

        if (($key = array_search($n, $cache[self::VARIABLE])) === false) {
            $key = count($cache[self::VARIABLE]);
            $cache[self::VARIABLE][] = $x;
            $cache[self::DATA][] = $this->_modInverse67108864($n);
        }

        $k = count($n);

        $result = array(self::VALUE => $x);

        for ($i = 0; $i < $k; ++$i) {
            $temp = $result[self::VALUE][$i] * $cache[self::DATA][$key];
            $temp = $temp - self::$baseFull * (self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31));
            $temp = $this->_regularMultiply(array($temp), $n);
            $temp = array_merge($this->_array_repeat(0, $i), $temp);
            $result = $this->_add($result[self::VALUE], false, $temp, false);
        }

        $result[self::VALUE] = array_slice($result[self::VALUE], $k);

        if ($this->_compare($result, false, $n, false) >= 0) {
            $result = $this->_subtract($result[self::VALUE], false, $n, false);
        }

        return $result[self::VALUE];
    }

    /**
     * Montgomery Multiply
     *
     * Interleaves the montgomery reduction and long multiplication algorithms together as described in
     * {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=13 HAC 14.36}
     *
     * @see self::_prepMontgomery()
     * @see self::_montgomery()
     * @access private
     * @param array $x
     * @param array $y
     * @param array $m
     * @return array
     */
    function _montgomeryMultiply($x, $y, $m)
    {
        $temp = $this->_multiply($x, false, $y, false);
        return $this->_montgomery($temp[self::VALUE], $m);

        // the following code, although not callable, can be run independently of the above code
        // although the above code performed better in my benchmarks the following could might
        // perform better under different circumstances. in lieu of deleting it it's just been
        // made uncallable

        static $cache = array(
            self::VARIABLE => array(),
            self::DATA => array()
        );

        if (($key = array_search($m, $cache[self::VARIABLE])) === false) {
            $key = count($cache[self::VARIABLE]);
            $cache[self::VARIABLE][] = $m;
            $cache[self::DATA][] = $this->_modInverse67108864($m);
        }

        $n = max(count($x), count($y), count($m));
        $x = array_pad($x, $n, 0);
        $y = array_pad($y, $n, 0);
        $m = array_pad($m, $n, 0);
        $a = array(self::VALUE => $this->_array_repeat(0, $n + 1));
        for ($i = 0; $i < $n; ++$i) {
            $temp = $a[self::VALUE][0] + $x[$i] * $y[0];
            $temp = $temp - self::$baseFull * (self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31));
            $temp = $temp * $cache[self::DATA][$key];
            $temp = $temp - self::$baseFull * (self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31));
            $temp = $this->_add($this->_regularMultiply(array($x[$i]), $y), false, $this->_regularMultiply(array($temp), $m), false);
            $a = $this->_add($a[self::VALUE], false, $temp[self::VALUE], false);
            $a[self::VALUE] = array_slice($a[self::VALUE], 1);
        }
        if ($this->_compare($a[self::VALUE], false, $m, false) >= 0) {
            $a = $this->_subtract($a[self::VALUE], false, $m, false);
        }
        return $a[self::VALUE];
    }

    /**
     * Prepare a number for use in Montgomery Modular Reductions
     *
     * @see self::_montgomery()
     * @see self::_slidingWindow()
     * @access private
     * @param array $x
     * @param array $n
     * @return array
     */
    function _prepMontgomery($x, $n)
    {
        $lhs = new static();
        $lhs->value = array_merge($this->_array_repeat(0, count($n)), $x);
        $rhs = new static();
        $rhs->value = $n;

        list(, $temp) = $lhs->divide($rhs);
        return $temp->value;
    }

    /**
     * Modular Inverse of a number mod 2**26 (eg. 67108864)
     *
     * Based off of the bnpInvDigit function implemented and justified in the following URL:
     *
     * {@link http://www-cs-students.stanford.edu/~tjw/jsbn/jsbn.js}
     *
     * The following URL provides more info:
     *
     * {@link http://groups.google.com/group/sci.crypt/msg/7a137205c1be7d85}
     *
     * As for why we do all the bitmasking...  strange things can happen when converting from floats to ints. For
     * instance, on some computers, var_dump((int) -4294967297) yields int(-1) and on others, it yields
     * int(-2147483648).  To avoid problems stemming from this, we use bitmasks to guarantee that ints aren't
     * auto-converted to floats.  The outermost bitmask is present because without it, there's no guarantee that
     * the "residue" returned would be the so-called "common residue".  We use fmod, in the last step, because the
     * maximum possible $x is 26 bits and the maximum $result is 16 bits.  Thus, we have to be able to handle up to
     * 40 bits, which only 64-bit floating points will support.
     *
     * Thanks to Pedro Gimeno Fortea for input!
     *
     * @see self::_montgomery()
     * @access private
     * @param array $x
     * @return int
     */
    function _modInverse67108864($x) // 2**26 == 67,108,864
    {
        $x = -$x[0];
        $result = $x & 0x3; // x**-1 mod 2**2
        $result = ($result * (2 - $x * $result)) & 0xF; // x**-1 mod 2**4
        $result = ($result * (2 - ($x & 0xFF) * $result))  & 0xFF; // x**-1 mod 2**8
        $result = ($result * ((2 - ($x & 0xFFFF) * $result) & 0xFFFF)) & 0xFFFF; // x**-1 mod 2**16
        $result = fmod($result * (2 - fmod($x * $result, self::$baseFull)), self::$baseFull); // x**-1 mod 2**26
        return $result & self::$maxDigit;
    }

    /**
     * Calculates modular inverses.
     *
     * Say you have (30 mod 17 * x mod 17) mod 17 == 1.  x can be found using modular inverses.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger(30);
     *    $b = new \phpseclib\Math\BigInteger(17);
     *
     *    $c = $a->modInverse($b);
     *    echo $c->toString(); // outputs 4
     *
     *    echo "\r\n";
     *
     *    $d = $a->multiply($c);
     *    list(, $d) = $d->divide($b);
     *    echo $d; // outputs 1 (as per the definition of modular inverse)
     * ?>
     * </code>
     *
     * @param \phpseclib\Math\BigInteger $n
     * @return \phpseclib\Math\BigInteger|false
     * @access public
     * @internal See {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=21 HAC 14.64} for more information.
     */
    function modInverse($n)
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                $temp = new static();
                $temp->value = gmp_invert($this->value, $n->value);

                return ($temp->value === false) ? false : $this->_normalize($temp);
        }

        static $zero, $one;
        if (!isset($zero)) {
            $zero = new static();
            $one = new static(1);
        }

        // $x mod -$n == $x mod $n.
        $n = $n->abs();

        if ($this->compare($zero) < 0) {
            $temp = $this->abs();
            $temp = $temp->modInverse($n);
            return $this->_normalize($n->subtract($temp));
        }

        extract($this->extendedGCD($n));

        if (!$gcd->equals($one)) {
            return false;
        }

        $x = $x->compare($zero) < 0 ? $x->add($n) : $x;

        return $this->compare($zero) < 0 ? $this->_normalize($n->subtract($x)) : $this->_normalize($x);
    }

    /**
     * Calculates the greatest common divisor and Bezout's identity.
     *
     * Say you have 693 and 609.  The GCD is 21.  Bezout's identity states that there exist integers x and y such that
     * 693*x + 609*y == 21.  In point of fact, there are actually an infinite number of x and y combinations and which
     * combination is returned is dependent upon which mode is in use.  See
     * {@link http://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity Bezout's identity - Wikipedia} for more information.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger(693);
     *    $b = new \phpseclib\Math\BigInteger(609);
     *
     *    extract($a->extendedGCD($b));
     *
     *    echo $gcd->toString() . "\r\n"; // outputs 21
     *    echo $a->toString() * $x->toString() + $b->toString() * $y->toString(); // outputs 21
     * ?>
     * </code>
     *
     * @param \phpseclib\Math\BigInteger $n
     * @return \phpseclib\Math\BigInteger
     * @access public
     * @internal Calculates the GCD using the binary xGCD algorithim described in
     *    {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=19 HAC 14.61}.  As the text above 14.61 notes,
     *    the more traditional algorithim requires "relatively costly multiple-precision divisions".
     */
    function extendedGCD($n)
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                extract(gmp_gcdext($this->value, $n->value));

                return array(
                    'gcd' => $this->_normalize(new static($g)),
                    'x'   => $this->_normalize(new static($s)),
                    'y'   => $this->_normalize(new static($t))
                );
            case self::MODE_BCMATH:
                // it might be faster to use the binary xGCD algorithim here, as well, but (1) that algorithim works
                // best when the base is a power of 2 and (2) i don't think it'd make much difference, anyway.  as is,
                // the basic extended euclidean algorithim is what we're using.

                $u = $this->value;
                $v = $n->value;

                $a = '1';
                $b = '0';
                $c = '0';
                $d = '1';

                while (bccomp($v, '0', 0) != 0) {
                    $q = bcdiv($u, $v, 0);

                    $temp = $u;
                    $u = $v;
                    $v = bcsub($temp, bcmul($v, $q, 0), 0);

                    $temp = $a;
                    $a = $c;
                    $c = bcsub($temp, bcmul($a, $q, 0), 0);

                    $temp = $b;
                    $b = $d;
                    $d = bcsub($temp, bcmul($b, $q, 0), 0);
                }

                return array(
                    'gcd' => $this->_normalize(new static($u)),
                    'x'   => $this->_normalize(new static($a)),
                    'y'   => $this->_normalize(new static($b))
                );
        }

        $y = $n->copy();
        $x = $this->copy();
        $g = new static();
        $g->value = array(1);

        while (!(($x->value[0] & 1)|| ($y->value[0] & 1))) {
            $x->_rshift(1);
            $y->_rshift(1);
            $g->_lshift(1);
        }

        $u = $x->copy();
        $v = $y->copy();

        $a = new static();
        $b = new static();
        $c = new static();
        $d = new static();

        $a->value = $d->value = $g->value = array(1);
        $b->value = $c->value = array();

        while (!empty($u->value)) {
            while (!($u->value[0] & 1)) {
                $u->_rshift(1);
                if ((!empty($a->value) && ($a->value[0] & 1)) || (!empty($b->value) && ($b->value[0] & 1))) {
                    $a = $a->add($y);
                    $b = $b->subtract($x);
                }
                $a->_rshift(1);
                $b->_rshift(1);
            }

            while (!($v->value[0] & 1)) {
                $v->_rshift(1);
                if ((!empty($d->value) && ($d->value[0] & 1)) || (!empty($c->value) && ($c->value[0] & 1))) {
                    $c = $c->add($y);
                    $d = $d->subtract($x);
                }
                $c->_rshift(1);
                $d->_rshift(1);
            }

            if ($u->compare($v) >= 0) {
                $u = $u->subtract($v);
                $a = $a->subtract($c);
                $b = $b->subtract($d);
            } else {
                $v = $v->subtract($u);
                $c = $c->subtract($a);
                $d = $d->subtract($b);
            }
        }

        return array(
            'gcd' => $this->_normalize($g->multiply($v)),
            'x'   => $this->_normalize($c),
            'y'   => $this->_normalize($d)
        );
    }

    /**
     * Calculates the greatest common divisor
     *
     * Say you have 693 and 609.  The GCD is 21.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger(693);
     *    $b = new \phpseclib\Math\BigInteger(609);
     *
     *    $gcd = a->extendedGCD($b);
     *
     *    echo $gcd->toString() . "\r\n"; // outputs 21
     * ?>
     * </code>
     *
     * @param \phpseclib\Math\BigInteger $n
     * @return \phpseclib\Math\BigInteger
     * @access public
     */
    function gcd($n)
    {
        extract($this->extendedGCD($n));
        return $gcd;
    }

    /**
     * Absolute value.
     *
     * @return \phpseclib\Math\BigInteger
     * @access public
     */
    function abs()
    {
        $temp = new static();

        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                $temp->value = gmp_abs($this->value);
                break;
            case self::MODE_BCMATH:
                $temp->value = (bccomp($this->value, '0', 0) < 0) ? substr($this->value, 1) : $this->value;
                break;
            default:
                $temp->value = $this->value;
        }

        return $temp;
    }

    /**
     * Compares two numbers.
     *
     * Although one might think !$x->compare($y) means $x != $y, it, in fact, means the opposite.  The reason for this is
     * demonstrated thusly:
     *
     * $x  > $y: $x->compare($y)  > 0
     * $x  < $y: $x->compare($y)  < 0
     * $x == $y: $x->compare($y) == 0
     *
     * Note how the same comparison operator is used.  If you want to test for equality, use $x->equals($y).
     *
     * @param \phpseclib\Math\BigInteger $y
     * @return int that is < 0 if $this is less than $y; > 0 if $this is greater than $y, and 0 if they are equal.
     * @access public
     * @see self::equals()
     * @internal Could return $this->subtract($x), but that's not as fast as what we do do.
     */
    function compare($y)
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                $r = gmp_cmp($this->value, $y->value);
                if ($r < -1) {
                    $r = -1;
                }
                if ($r > 1) {
                    $r = 1;
                }
                return $r;
            case self::MODE_BCMATH:
                return bccomp($this->value, $y->value, 0);
        }

        return $this->_compare($this->value, $this->is_negative, $y->value, $y->is_negative);
    }

    /**
     * Compares two numbers.
     *
     * @param array $x_value
     * @param bool $x_negative
     * @param array $y_value
     * @param bool $y_negative
     * @return int
     * @see self::compare()
     * @access private
     */
    function _compare($x_value, $x_negative, $y_value, $y_negative)
    {
        if ($x_negative != $y_negative) {
            return (!$x_negative && $y_negative) ? 1 : -1;
        }

        $result = $x_negative ? -1 : 1;

        if (count($x_value) != count($y_value)) {
            return (count($x_value) > count($y_value)) ? $result : -$result;
        }
        $size = max(count($x_value), count($y_value));

        $x_value = array_pad($x_value, $size, 0);
        $y_value = array_pad($y_value, $size, 0);

        for ($i = count($x_value) - 1; $i >= 0; --$i) {
            if ($x_value[$i] != $y_value[$i]) {
                return ($x_value[$i] > $y_value[$i]) ? $result : -$result;
            }
        }

        return 0;
    }

    /**
     * Tests the equality of two numbers.
     *
     * If you need to see if one number is greater than or less than another number, use BigInteger::compare()
     *
     * @param \phpseclib\Math\BigInteger $x
     * @return bool
     * @access public
     * @see self::compare()
     */
    function equals($x)
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                return gmp_cmp($this->value, $x->value) == 0;
            default:
                return $this->value === $x->value && $this->is_negative == $x->is_negative;
        }
    }

    /**
     * Set Precision
     *
     * Some bitwise operations give different results depending on the precision being used.  Examples include left
     * shift, not, and rotates.
     *
     * @param int $bits
     * @access public
     */
    function setPrecision($bits)
    {
        $this->precision = $bits;
        if (MATH_BIGINTEGER_MODE != self::MODE_BCMATH) {
            $this->bitmask = new static(chr((1 << ($bits & 0x7)) - 1) . str_repeat(chr(0xFF), $bits >> 3), 256);
        } else {
            $this->bitmask = new static(bcpow('2', $bits, 0));
        }

        $temp = $this->_normalize($this);
        $this->value = $temp->value;
    }

    /**
     * Logical And
     *
     * @param \phpseclib\Math\BigInteger $x
     * @access public
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     * @return \phpseclib\Math\BigInteger
     */
    function bitwise_and($x)
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                $temp = new static();
                $temp->value = gmp_and($this->value, $x->value);

                return $this->_normalize($temp);
            case self::MODE_BCMATH:
                $left = $this->toBytes();
                $right = $x->toBytes();

                $length = max(strlen($left), strlen($right));

                $left = str_pad($left, $length, chr(0), STR_PAD_LEFT);
                $right = str_pad($right, $length, chr(0), STR_PAD_LEFT);

                return $this->_normalize(new static($left & $right, 256));
        }

        $result = $this->copy();

        $length = min(count($x->value), count($this->value));

        $result->value = array_slice($result->value, 0, $length);

        for ($i = 0; $i < $length; ++$i) {
            $result->value[$i]&= $x->value[$i];
        }

        return $this->_normalize($result);
    }

    /**
     * Logical Or
     *
     * @param \phpseclib\Math\BigInteger $x
     * @access public
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     * @return \phpseclib\Math\BigInteger
     */
    function bitwise_or($x)
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                $temp = new static();
                $temp->value = gmp_or($this->value, $x->value);

                return $this->_normalize($temp);
            case self::MODE_BCMATH:
                $left = $this->toBytes();
                $right = $x->toBytes();

                $length = max(strlen($left), strlen($right));

                $left = str_pad($left, $length, chr(0), STR_PAD_LEFT);
                $right = str_pad($right, $length, chr(0), STR_PAD_LEFT);

                return $this->_normalize(new static($left | $right, 256));
        }

        $length = max(count($this->value), count($x->value));
        $result = $this->copy();
        $result->value = array_pad($result->value, $length, 0);
        $x->value = array_pad($x->value, $length, 0);

        for ($i = 0; $i < $length; ++$i) {
            $result->value[$i]|= $x->value[$i];
        }

        return $this->_normalize($result);
    }

    /**
     * Logical Exclusive-Or
     *
     * @param \phpseclib\Math\BigInteger $x
     * @access public
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     * @return \phpseclib\Math\BigInteger
     */
    function bitwise_xor($x)
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                $temp = new static();
                $temp->value = gmp_xor(gmp_abs($this->value), gmp_abs($x->value));
                return $this->_normalize($temp);
            case self::MODE_BCMATH:
                $left = $this->toBytes();
                $right = $x->toBytes();

                $length = max(strlen($left), strlen($right));

                $left = str_pad($left, $length, chr(0), STR_PAD_LEFT);
                $right = str_pad($right, $length, chr(0), STR_PAD_LEFT);

                return $this->_normalize(new static($left ^ $right, 256));
        }

        $length = max(count($this->value), count($x->value));
        $result = $this->copy();
        $result->is_negative = false;
        $result->value = array_pad($result->value, $length, 0);
        $x->value = array_pad($x->value, $length, 0);

        for ($i = 0; $i < $length; ++$i) {
            $result->value[$i]^= $x->value[$i];
        }

        return $this->_normalize($result);
    }

    /**
     * Logical Not
     *
     * @access public
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     * @return \phpseclib\Math\BigInteger
     */
    function bitwise_not()
    {
        // calculuate "not" without regard to $this->precision
        // (will always result in a smaller number.  ie. ~1 isn't 1111 1110 - it's 0)
        $temp = $this->toBytes();
        if ($temp == '') {
            return $this->_normalize(new static());
        }
        $pre_msb = decbin(ord($temp[0]));
        $temp = ~$temp;
        $msb = decbin(ord($temp[0]));
        if (strlen($msb) == 8) {
            $msb = substr($msb, strpos($msb, '0'));
        }
        $temp[0] = chr(bindec($msb));

        // see if we need to add extra leading 1's
        $current_bits = strlen($pre_msb) + 8 * strlen($temp) - 8;
        $new_bits = $this->precision - $current_bits;
        if ($new_bits <= 0) {
            return $this->_normalize(new static($temp, 256));
        }

        // generate as many leading 1's as we need to.
        $leading_ones = chr((1 << ($new_bits & 0x7)) - 1) . str_repeat(chr(0xFF), $new_bits >> 3);
        $this->_base256_lshift($leading_ones, $current_bits);

        $temp = str_pad($temp, strlen($leading_ones), chr(0), STR_PAD_LEFT);

        return $this->_normalize(new static($leading_ones | $temp, 256));
    }

    /**
     * Logical Right Shift
     *
     * Shifts BigInteger's by $shift bits, effectively dividing by 2**$shift.
     *
     * @param int $shift
     * @return \phpseclib\Math\BigInteger
     * @access public
     * @internal The only version that yields any speed increases is the internal version.
     */
    function bitwise_rightShift($shift)
    {
        $temp = new static();

        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                static $two;

                if (!isset($two)) {
                    $two = gmp_init('2');
                }

                $temp->value = gmp_div_q($this->value, gmp_pow($two, $shift));

                break;
            case self::MODE_BCMATH:
                $temp->value = bcdiv($this->value, bcpow('2', $shift, 0), 0);

                break;
            default: // could just replace _lshift with this, but then all _lshift() calls would need to be rewritten
                     // and I don't want to do that...
                $temp->value = $this->value;
                $temp->_rshift($shift);
        }

        return $this->_normalize($temp);
    }

    /**
     * Logical Left Shift
     *
     * Shifts BigInteger's by $shift bits, effectively multiplying by 2**$shift.
     *
     * @param int $shift
     * @return \phpseclib\Math\BigInteger
     * @access public
     * @internal The only version that yields any speed increases is the internal version.
     */
    function bitwise_leftShift($shift)
    {
        $temp = new static();

        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                static $two;

                if (!isset($two)) {
                    $two = gmp_init('2');
                }

                $temp->value = gmp_mul($this->value, gmp_pow($two, $shift));

                break;
            case self::MODE_BCMATH:
                $temp->value = bcmul($this->value, bcpow('2', $shift, 0), 0);

                break;
            default: // could just replace _rshift with this, but then all _lshift() calls would need to be rewritten
                     // and I don't want to do that...
                $temp->value = $this->value;
                $temp->_lshift($shift);
        }

        return $this->_normalize($temp);
    }

    /**
     * Logical Left Rotate
     *
     * Instead of the top x bits being dropped they're appended to the shifted bit string.
     *
     * @param int $shift
     * @return \phpseclib\Math\BigInteger
     * @access public
     */
    function bitwise_leftRotate($shift)
    {
        $bits = $this->toBytes();

        if ($this->precision > 0) {
            $precision = $this->precision;
            if (MATH_BIGINTEGER_MODE == self::MODE_BCMATH) {
                $mask = $this->bitmask->subtract(new static(1));
                $mask = $mask->toBytes();
            } else {
                $mask = $this->bitmask->toBytes();
            }
        } else {
            $temp = ord($bits[0]);
            for ($i = 0; $temp >> $i; ++$i) {
            }
            $precision = 8 * strlen($bits) - 8 + $i;
            $mask = chr((1 << ($precision & 0x7)) - 1) . str_repeat(chr(0xFF), $precision >> 3);
        }

        if ($shift < 0) {
            $shift+= $precision;
        }
        $shift%= $precision;

        if (!$shift) {
            return $this->copy();
        }

        $left = $this->bitwise_leftShift($shift);
        $left = $left->bitwise_and(new static($mask, 256));
        $right = $this->bitwise_rightShift($precision - $shift);
        $result = MATH_BIGINTEGER_MODE != self::MODE_BCMATH ? $left->bitwise_or($right) : $left->add($right);
        return $this->_normalize($result);
    }

    /**
     * Logical Right Rotate
     *
     * Instead of the bottom x bits being dropped they're prepended to the shifted bit string.
     *
     * @param int $shift
     * @return \phpseclib\Math\BigInteger
     * @access public
     */
    function bitwise_rightRotate($shift)
    {
        return $this->bitwise_leftRotate(-$shift);
    }

    /**
     * Generates a random BigInteger
     *
     * Byte length is equal to $length. Uses \phpseclib\Crypt\Random if it's loaded and mt_rand if it's not.
     *
     * @param int $size
     * @return \phpseclib\Math\BigInteger
     * @access private
     */
    function _random_number_helper($size)
    {
        if (class_exists('\phpseclib\Crypt\Random')) {
            $random = Random::string($size);
        } else {
            $random = '';

            if ($size & 1) {
                $random.= chr(mt_rand(0, 255));
            }

            $blocks = $size >> 1;
            for ($i = 0; $i < $blocks; ++$i) {
                // mt_rand(-2147483648, 0x7FFFFFFF) always produces -2147483648 on some systems
                $random.= pack('n', mt_rand(0, 0xFFFF));
            }
        }

        return new static($random, 256);
    }

    /**
     * Generate a random number
     *
     * Returns a random number between $min and $max where $min and $max
     * can be defined using one of the two methods:
     *
     * $min->random($max)
     * $max->random($min)
     *
     * @param \phpseclib\Math\BigInteger $arg1
     * @param \phpseclib\Math\BigInteger $arg2
     * @return \phpseclib\Math\BigInteger
     * @access public
     * @internal The API for creating random numbers used to be $a->random($min, $max), where $a was a BigInteger object.
     *           That method is still supported for BC purposes.
     */
    function random($arg1, $arg2 = false)
    {
        if ($arg1 === false) {
            return false;
        }

        if ($arg2 === false) {
            $max = $arg1;
            $min = $this;
        } else {
            $min = $arg1;
            $max = $arg2;
        }

        $compare = $max->compare($min);

        if (!$compare) {
            return $this->_normalize($min);
        } elseif ($compare < 0) {
            // if $min is bigger then $max, swap $min and $max
            $temp = $max;
            $max = $min;
            $min = $temp;
        }

        static $one;
        if (!isset($one)) {
            $one = new static(1);
        }

        $max = $max->subtract($min->subtract($one));
        $size = strlen(ltrim($max->toBytes(), chr(0)));

        /*
            doing $random % $max doesn't work because some numbers will be more likely to occur than others.
            eg. if $max is 140 and $random's max is 255 then that'd mean both $random = 5 and $random = 145
            would produce 5 whereas the only value of random that could produce 139 would be 139. ie.
            not all numbers would be equally likely. some would be more likely than others.

            creating a whole new random number until you find one that is within the range doesn't work
            because, for sufficiently small ranges, the likelihood that you'd get a number within that range
            would be pretty small. eg. with $random's max being 255 and if your $max being 1 the probability
            would be pretty high that $random would be greater than $max.

            phpseclib works around this using the technique described here:

            http://crypto.stackexchange.com/questions/5708/creating-a-small-number-from-a-cryptographically-secure-random-string
        */
        $random_max = new static(chr(1) . str_repeat("\0", $size), 256);
        $random = $this->_random_number_helper($size);

        list($max_multiple) = $random_max->divide($max);
        $max_multiple = $max_multiple->multiply($max);

        while ($random->compare($max_multiple) >= 0) {
            $random = $random->subtract($max_multiple);
            $random_max = $random_max->subtract($max_multiple);
            $random = $random->bitwise_leftShift(8);
            $random = $random->add($this->_random_number_helper(1));
            $random_max = $random_max->bitwise_leftShift(8);
            list($max_multiple) = $random_max->divide($max);
            $max_multiple = $max_multiple->multiply($max);
        }
        list(, $random) = $random->divide($max);

        return $this->_normalize($random->add($min));
    }

    /**
     * Generate a random prime number.
     *
     * If there's not a prime within the given range, false will be returned.
     * If more than $timeout seconds have elapsed, give up and return false.
     *
     * @param \phpseclib\Math\BigInteger $arg1
     * @param \phpseclib\Math\BigInteger $arg2
     * @param int $timeout
     * @return Math_BigInteger|false
     * @access public
     * @internal See {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap4.pdf#page=15 HAC 4.44}.
     */
    function randomPrime($arg1, $arg2 = false, $timeout = false)
    {
        if ($arg1 === false) {
            return false;
        }

        if ($arg2 === false) {
            $max = $arg1;
            $min = $this;
        } else {
            $min = $arg1;
            $max = $arg2;
        }

        $compare = $max->compare($min);

        if (!$compare) {
            return $min->isPrime() ? $min : false;
        } elseif ($compare < 0) {
            // if $min is bigger then $max, swap $min and $max
            $temp = $max;
            $max = $min;
            $min = $temp;
        }

        static $one, $two;
        if (!isset($one)) {
            $one = new static(1);
            $two = new static(2);
        }

        $start = time();

        $x = $this->random($min, $max);

        // gmp_nextprime() requires PHP 5 >= 5.2.0 per <http://php.net/gmp-nextprime>.
        if (MATH_BIGINTEGER_MODE == self::MODE_GMP && extension_loaded('gmp')) {
            $p = new static();
            $p->value = gmp_nextprime($x->value);

            if ($p->compare($max) <= 0) {
                return $p;
            }

            if (!$min->equals($x)) {
                $x = $x->subtract($one);
            }

            return $x->randomPrime($min, $x);
        }

        if ($x->equals($two)) {
            return $x;
        }

        $x->_make_odd();
        if ($x->compare($max) > 0) {
            // if $x > $max then $max is even and if $min == $max then no prime number exists between the specified range
            if ($min->equals($max)) {
                return false;
            }
            $x = $min->copy();
            $x->_make_odd();
        }

        $initial_x = $x->copy();

        while (true) {
            if ($timeout !== false && time() - $start > $timeout) {
                return false;
            }

            if ($x->isPrime()) {
                return $x;
            }

            $x = $x->add($two);

            if ($x->compare($max) > 0) {
                $x = $min->copy();
                if ($x->equals($two)) {
                    return $x;
                }
                $x->_make_odd();
            }

            if ($x->equals($initial_x)) {
                return false;
            }
        }
    }

    /**
     * Make the current number odd
     *
     * If the current number is odd it'll be unchanged.  If it's even, one will be added to it.
     *
     * @see self::randomPrime()
     * @access private
     */
    function _make_odd()
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                gmp_setbit($this->value, 0);
                break;
            case self::MODE_BCMATH:
                if ($this->value[strlen($this->value) - 1] % 2 == 0) {
                    $this->value = bcadd($this->value, '1');
                }
                break;
            default:
                $this->value[0] |= 1;
        }
    }

    /**
     * Checks a numer to see if it's prime
     *
     * Assuming the $t parameter is not set, this function has an error rate of 2**-80.  The main motivation for the
     * $t parameter is distributability.  BigInteger::randomPrime() can be distributed across multiple pageloads
     * on a website instead of just one.
     *
     * @param \phpseclib\Math\BigInteger $t
     * @return bool
     * @access public
     * @internal Uses the
     *     {@link http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test Miller-Rabin primality test}.  See
     *     {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap4.pdf#page=8 HAC 4.24}.
     */
    function isPrime($t = false)
    {
        $length = strlen($this->toBytes());

        if (!$t) {
            // see HAC 4.49 "Note (controlling the error probability)"
            // @codingStandardsIgnoreStart
                 if ($length >= 163) { $t =  2; } // floor(1300 / 8)
            else if ($length >= 106) { $t =  3; } // floor( 850 / 8)
            else if ($length >= 81 ) { $t =  4; } // floor( 650 / 8)
            else if ($length >= 68 ) { $t =  5; } // floor( 550 / 8)
            else if ($length >= 56 ) { $t =  6; } // floor( 450 / 8)
            else if ($length >= 50 ) { $t =  7; } // floor( 400 / 8)
            else if ($length >= 43 ) { $t =  8; } // floor( 350 / 8)
            else if ($length >= 37 ) { $t =  9; } // floor( 300 / 8)
            else if ($length >= 31 ) { $t = 12; } // floor( 250 / 8)
            else if ($length >= 25 ) { $t = 15; } // floor( 200 / 8)
            else if ($length >= 18 ) { $t = 18; } // floor( 150 / 8)
            else                     { $t = 27; }
            // @codingStandardsIgnoreEnd
        }

        // ie. gmp_testbit($this, 0)
        // ie. isEven() or !isOdd()
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                return gmp_prob_prime($this->value, $t) != 0;
            case self::MODE_BCMATH:
                if ($this->value === '2') {
                    return true;
                }
                if ($this->value[strlen($this->value) - 1] % 2 == 0) {
                    return false;
                }
                break;
            default:
                if ($this->value == array(2)) {
                    return true;
                }
                if (~$this->value[0] & 1) {
                    return false;
                }
        }

        static $primes, $zero, $one, $two;

        if (!isset($primes)) {
            $primes = array(
                3,    5,    7,    11,   13,   17,   19,   23,   29,   31,   37,   41,   43,   47,   53,   59,
                61,   67,   71,   73,   79,   83,   89,   97,   101,  103,  107,  109,  113,  127,  131,  137,
                139,  149,  151,  157,  163,  167,  173,  179,  181,  191,  193,  197,  199,  211,  223,  227,
                229,  233,  239,  241,  251,  257,  263,  269,  271,  277,  281,  283,  293,  307,  311,  313,
                317,  331,  337,  347,  349,  353,  359,  367,  373,  379,  383,  389,  397,  401,  409,  419,
                421,  431,  433,  439,  443,  449,  457,  461,  463,  467,  479,  487,  491,  499,  503,  509,
                521,  523,  541,  547,  557,  563,  569,  571,  577,  587,  593,  599,  601,  607,  613,  617,
                619,  631,  641,  643,  647,  653,  659,  661,  673,  677,  683,  691,  701,  709,  719,  727,
                733,  739,  743,  751,  757,  761,  769,  773,  787,  797,  809,  811,  821,  823,  827,  829,
                839,  853,  857,  859,  863,  877,  881,  883,  887,  907,  911,  919,  929,  937,  941,  947,
                953,  967,  971,  977,  983,  991,  997
            );

            if (MATH_BIGINTEGER_MODE != self::MODE_INTERNAL) {
                for ($i = 0; $i < count($primes); ++$i) {
                    $primes[$i] = new static($primes[$i]);
                }
            }

            $zero = new static();
            $one = new static(1);
            $two = new static(2);
        }

        if ($this->equals($one)) {
            return false;
        }

        // see HAC 4.4.1 "Random search for probable primes"
        if (MATH_BIGINTEGER_MODE != self::MODE_INTERNAL) {
            foreach ($primes as $prime) {
                list(, $r) = $this->divide($prime);
                if ($r->equals($zero)) {
                    return $this->equals($prime);
                }
            }
        } else {
            $value = $this->value;
            foreach ($primes as $prime) {
                list(, $r) = $this->_divide_digit($value, $prime);
                if (!$r) {
                    return count($value) == 1 && $value[0] == $prime;
                }
            }
        }

        $n   = $this->copy();
        $n_1 = $n->subtract($one);
        $n_2 = $n->subtract($two);

        $r = $n_1->copy();
        $r_value = $r->value;
        // ie. $s = gmp_scan1($n, 0) and $r = gmp_div_q($n, gmp_pow(gmp_init('2'), $s));
        if (MATH_BIGINTEGER_MODE == self::MODE_BCMATH) {
            $s = 0;
            // if $n was 1, $r would be 0 and this would be an infinite loop, hence our $this->equals($one) check earlier
            while ($r->value[strlen($r->value) - 1] % 2 == 0) {
                $r->value = bcdiv($r->value, '2', 0);
                ++$s;
            }
        } else {
            for ($i = 0, $r_length = count($r_value); $i < $r_length; ++$i) {
                $temp = ~$r_value[$i] & 0xFFFFFF;
                for ($j = 1; ($temp >> $j) & 1; ++$j) {
                }
                if ($j != 25) {
                    break;
                }
            }
            $s = 26 * $i + $j;
            $r->_rshift($s);
        }

        for ($i = 0; $i < $t; ++$i) {
            $a = $this->random($two, $n_2);
            $y = $a->modPow($r, $n);

            if (!$y->equals($one) && !$y->equals($n_1)) {
                for ($j = 1; $j < $s && !$y->equals($n_1); ++$j) {
                    $y = $y->modPow($two, $n);
                    if ($y->equals($one)) {
                        return false;
                    }
                }

                if (!$y->equals($n_1)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Logical Left Shift
     *
     * Shifts BigInteger's by $shift bits.
     *
     * @param int $shift
     * @access private
     */
    function _lshift($shift)
    {
        if ($shift == 0) {
            return;
        }

        $num_digits = (int) ($shift / self::$base);
        $shift %= self::$base;
        $shift = 1 << $shift;

        $carry = 0;

        for ($i = 0; $i < count($this->value); ++$i) {
            $temp = $this->value[$i] * $shift + $carry;
            $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
            $this->value[$i] = (int) ($temp - $carry * self::$baseFull);
        }

        if ($carry) {
            $this->value[count($this->value)] = $carry;
        }

        while ($num_digits--) {
            array_unshift($this->value, 0);
        }
    }

    /**
     * Logical Right Shift
     *
     * Shifts BigInteger's by $shift bits.
     *
     * @param int $shift
     * @access private
     */
    function _rshift($shift)
    {
        if ($shift == 0) {
            return;
        }

        $num_digits = (int) ($shift / self::$base);
        $shift %= self::$base;
        $carry_shift = self::$base - $shift;
        $carry_mask = (1 << $shift) - 1;

        if ($num_digits) {
            $this->value = array_slice($this->value, $num_digits);
        }

        $carry = 0;

        for ($i = count($this->value) - 1; $i >= 0; --$i) {
            $temp = $this->value[$i] >> $shift | $carry;
            $carry = ($this->value[$i] & $carry_mask) << $carry_shift;
            $this->value[$i] = $temp;
        }

        $this->value = $this->_trim($this->value);
    }

    /**
     * Normalize
     *
     * Removes leading zeros and truncates (if necessary) to maintain the appropriate precision
     *
     * @param \phpseclib\Math\BigInteger $result
     * @return \phpseclib\Math\BigInteger
     * @see self::_trim()
     * @access private
     */
    function _normalize($result)
    {
        $result->precision = $this->precision;
        $result->bitmask = $this->bitmask;

        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                if ($this->bitmask !== false) {
                    $flip = gmp_cmp($result->value, gmp_init(0)) < 0;
                    if ($flip) {
                        $result->value = gmp_neg($result->value);
                    }
                    $result->value = gmp_and($result->value, $result->bitmask->value);
                    if ($flip) {
                        $result->value = gmp_neg($result->value);
                    }
                }

                return $result;
            case self::MODE_BCMATH:
                if (!empty($result->bitmask->value)) {
                    $result->value = bcmod($result->value, $result->bitmask->value);
                }

                return $result;
        }

        $value = &$result->value;

        if (!count($value)) {
            $result->is_negative = false;
            return $result;
        }

        $value = $this->_trim($value);

        if (!empty($result->bitmask->value)) {
            $length = min(count($value), count($this->bitmask->value));
            $value = array_slice($value, 0, $length);

            for ($i = 0; $i < $length; ++$i) {
                $value[$i] = $value[$i] & $this->bitmask->value[$i];
            }
        }

        return $result;
    }

    /**
     * Trim
     *
     * Removes leading zeros
     *
     * @param array $value
     * @return \phpseclib\Math\BigInteger
     * @access private
     */
    function _trim($value)
    {
        for ($i = count($value) - 1; $i >= 0; --$i) {
            if ($value[$i]) {
                break;
            }
            unset($value[$i]);
        }

        return $value;
    }

    /**
     * Array Repeat
     *
     * @param array $input
     * @param mixed $multiplier
     * @return array
     * @access private
     */
    function _array_repeat($input, $multiplier)
    {
        return ($multiplier) ? array_fill(0, $multiplier, $input) : array();
    }

    /**
     * Logical Left Shift
     *
     * Shifts binary strings $shift bits, essentially multiplying by 2**$shift.
     *
     * @param string $x (by reference)
     * @param int $shift
     * @return string
     * @access private
     */
    function _base256_lshift(&$x, $shift)
    {
        if ($shift == 0) {
            return;
        }

        $num_bytes = $shift >> 3; // eg. floor($shift/8)
        $shift &= 7; // eg. $shift % 8

        $carry = 0;
        for ($i = strlen($x) - 1; $i >= 0; --$i) {
            $temp = ord($x[$i]) << $shift | $carry;
            $x[$i] = chr($temp);
            $carry = $temp >> 8;
        }
        $carry = ($carry != 0) ? chr($carry) : '';
        $x = $carry . $x . str_repeat(chr(0), $num_bytes);
    }

    /**
     * Logical Right Shift
     *
     * Shifts binary strings $shift bits, essentially dividing by 2**$shift and returning the remainder.
     *
     * @param string $x (by referenc)
     * @param int $shift
     * @return string
     * @access private
     */
    function _base256_rshift(&$x, $shift)
    {
        if ($shift == 0) {
            $x = ltrim($x, chr(0));
            return '';
        }

        $num_bytes = $shift >> 3; // eg. floor($shift/8)
        $shift &= 7; // eg. $shift % 8

        $remainder = '';
        if ($num_bytes) {
            $start = $num_bytes > strlen($x) ? -strlen($x) : -$num_bytes;
            $remainder = substr($x, $start);
            $x = substr($x, 0, -$num_bytes);
        }

        $carry = 0;
        $carry_shift = 8 - $shift;
        for ($i = 0; $i < strlen($x); ++$i) {
            $temp = (ord($x[$i]) >> $shift) | $carry;
            $carry = (ord($x[$i]) << $carry_shift) & 0xFF;
            $x[$i] = chr($temp);
        }
        $x = ltrim($x, chr(0));

        $remainder = chr($carry >> $carry_shift) . $remainder;

        return ltrim($remainder, chr(0));
    }

    // one quirk about how the following functions are implemented is that PHP defines N to be an unsigned long
    // at 32-bits, while java's longs are 64-bits.

    /**
     * Converts 32-bit integers to bytes.
     *
     * @param int $x
     * @return string
     * @access private
     */
    function _int2bytes($x)
    {
        return ltrim(pack('N', $x), chr(0));
    }

    /**
     * Converts bytes to 32-bit integers
     *
     * @param string $x
     * @return int
     * @access private
     */
    function _bytes2int($x)
    {
        $temp = unpack('Nint', str_pad($x, 4, chr(0), STR_PAD_LEFT));
        return $temp['int'];
    }

    /**
     * DER-encode an integer
     *
     * The ability to DER-encode integers is needed to create RSA public keys for use with OpenSSL
     *
     * @see self::modPow()
     * @access private
     * @param int $length
     * @return string
     */
    function _encodeASN1Length($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }

    /**
     * Single digit division
     *
     * Even if int64 is being used the division operator will return a float64 value
     * if the dividend is not evenly divisible by the divisor. Since a float64 doesn't
     * have the precision of int64 this is a problem so, when int64 is being used,
     * we'll guarantee that the dividend is divisible by first subtracting the remainder.
     *
     * @access private
     * @param int $x
     * @param int $y
     * @return int
     */
    function _safe_divide($x, $y)
    {
        if (self::$base === 26) {
            return (int) ($x / $y);
        }

        // self::$base === 31
        return ($x - ($x % $y)) / $y;
    }
}
