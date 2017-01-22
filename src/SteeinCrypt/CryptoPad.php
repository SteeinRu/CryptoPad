<?php
namespace SteeinCrypt;

use SteeinCrypt\Exceptions\CryptoPadException;

/**
 *
 * CryptPad - позволяет безопасно шифровать / дешифровать информацию
 * Этот компонент обеспечивает безопасное шифрование с использованием AES-256-CBC.
 *
 * @see http://www.php.net/manual/en/book.openssl.php
 *
 * @package     SteeinCrypt
 *
 * @author      Shamsudin Serderov
 * @url         https://steein.ru
 *
 * @copyright   2017 - Steein Inc
 * @version     1.0.0
 *
 */

class CryptoPad implements CryptoPadInterface
{
    /***
     * @var string
     */
    protected $version       =  '1.0.0';

    /***
     * @var string
    */
    protected $key           =  '';

    /***
     * @var integer
     */
    protected $padding       =  0;

    /***
     * Метод шифрования данных
     *
     * @var string
     */
    protected $cipher        =  "aes-256-cbc";

    /***
     * @const ansi_x_923
     */
    const ansi_x_923         =   1;

    /***
     * @const pkcs7
     */
    const pkcs7              =   2;

    /***
     * @const iso_10126
     */
    const iso_10126          =   3;

    /***
     * @const iso_iec_7816_4
     */
    const iso_iec_7816_4     =   4;

    /***
     * @const zero
     */
    const zero               =   5;

    /***
     * @const space
     */
    const space              =   6;


    /**
     * Устанавливает алгоритм шифрования
     *
     * @param string $cipher
     *
     * @return $this | CryptoPadInterface
     */
    public function setCipher(string $cipher) : CryptoPadInterface
    {
        $this->cipher = $cipher;
        return $this;
    }

    /**
     * Возвращает текущее шифрование
     *
     * @return string
     */
    public function getCipher() : string
    {
        return $this->cipher;
    }

    /**
     * Установка ключа шифрования
     *
     * @param string $key
     * @return CryptoPad
     */
    public function setKey(string $key) : CryptoPad
    {
        $this->key = $key;
        return $this;
    }

    /**
     * Возвращает ключ шифрования
     *
     * @return string
     */
    public function getKey() : string
    {
        return $this->key;
    }

    /**
     * Обработка текста перед шифрованием
     *
     * @see http://www.di-mgt.com.au/cryptopad.html
     *
     * @param $text
     * @param $mode
     * @param $blockSize
     * @param $paddingType
     * @return string
     * @throws CryptoPadException
     */
    protected function padText(string $text, string $mode, int $blockSize, int $paddingType)
    {
        $paddingSize = 0;
        $padding     = null;

        if ($mode == "cbc" || $mode == "ecb")
        {
            $paddingSize = $blockSize - (strlen($text) % $blockSize);
            if ($paddingSize >= 256)
                throw new CryptoPadException("Block size is bigger than 256");

            switch ($paddingType)
            {
                case self::ansi_x_923:
                    $padding = str_repeat(chr(0), $paddingSize - 1) . chr($paddingSize);
					break;

                case self::pkcs7:
                    $padding = str_repeat(chr($paddingSize), $paddingSize);
					break;

                case self::iso_10126:
                    $padding = "";
                    for($i = 0; \range(0, $paddingSize -2); $i++)
                        $padding .= \chr(\rand());

					$padding .= chr($paddingSize);
					break;

				case self::iso_iec_7816_4:
					$padding = chr(0x80) . str_repeat(chr(0), $paddingSize - 1);
					break;

				case self::zero:
					$padding = str_repeat(chr(0), $paddingSize);
					break;

				case self::space:
					$padding = str_repeat(" ", $paddingSize);
					break;

				default:
					$paddingSize = 0;
					break;
			}
		}

        if (!$paddingSize)
            return $text;

        if ($paddingSize > $blockSize)
            throw new CryptoPadException("Invalid padding size");

        return $text . substr($padding, 0, $paddingSize);
    }

    /**
     * Удаляет @a padding_type из @a text
     * Если функция обнаруживает, что текст не был дополнен, он будет возвращать его неизмененной
     *
     * @param string $text
     * @param string $mode
     * @param int    $blockSize
     * @param int    $paddingType
     * @return string
     */
    protected function unPadText(string $text, string $mode, int $blockSize, int $paddingType)
    {
        $paddingSize = 0;
        $length = \strlen($text);

        if($length > 0 && ($length % $blockSize == 0) && ($mode == "cbc" || $mode == "ecb"))
        {
            switch ($paddingType)
            {
                case self::ansi_x_923:
                    $last = \substr($text, $length - 1, 1);
                    $ord = (int) \ord($last);
                    if($ord <= $blockSize)
                    {
                        $paddingSize = $ord;
                        $padding = \str_repeat(\chr(0), $paddingSize - 1) . $last;
                        if (\substr($text, $length - $paddingSize) != $padding)
                        {
                            $paddingSize = 0;
                        }
                    }
                    break;

                case self::pkcs7:
                    $last = \substr($text, $length - 1, 1);
                    $ord = (int) \ord($last);
                    if ($ord <= $blockSize)
                    {
                        $paddingSize = $ord;
                        $padding = \str_repeat(\chr($paddingSize), $paddingSize);
                        if (\substr($text, $length - $paddingSize) != $padding)
                        {
                            $paddingSize = 0;
                        }
                    }
                    break;

                case self::iso_10126:
                    $last = \substr($text, $length - 1, 1);
                    $paddingSize = (int) \ord($last);
                    break;

                case self::iso_iec_7816_4:
                    $i = $length - 1;
                    while($i > 0 && $text[$i] == 0x00 && $paddingSize < $blockSize)
                    {
                        $paddingSize++;
                        $i--;
                    }
                    if ($text[$i] == 0x80) {
                        $paddingSize++;
                    } else {
                        $paddingSize = 0;
                    }
                    break;

                case self::zero:
                    $i = $length - 1;
                    while ($i >= 0 && $text[$i] == 0x00 && $paddingSize <= $blockSize)
                    {
                        $paddingSize++;
                        $i--;
                    }
                    break;

                case self::space:
                    $i = $length - 1;
                    while ($i >= 0 && $text[$i] == 0x20 && $paddingSize <= $blockSize)
                    {
                        $paddingSize++;
                        $i--;
                    }
                    break;

                default:
                    break;
            }

            if($paddingSize && $paddingSize <= $blockSize) {

                if ($paddingSize < $length) {
                    return \substr($text, 0, $length - $paddingSize);
                }
                return "";

            }
        }
        return $text;
    }

    /**
     * Шифрование текста
     *
     * @param $text
     * @param $key
     * @return string
     * @throws CryptoPadException
     */
    public function encrypt(string $text, $key = null) : string
    {
        if (!\function_exists("openssl_cipher_iv_length")) {
            throw new CryptoPadException("openssl extension is required");
        }

        if ($key === null) {
            $encryptKey = $this->key;
		} else {
            $encryptKey = $key;
		}

        if (empty($encryptKey)) {
            throw new CryptoPadException("Encryption key cannot be empty");
        }

        $cipher = $this->cipher;
		$mode = strtolower(substr($cipher, strrpos($cipher, "-") - strlen($cipher)));

		if (!in_array($cipher, openssl_get_cipher_methods())) {
			throw new CryptoPadException("Cipher algorithm is unknown");
		}

		$ivSize = openssl_cipher_iv_length($cipher);
		if ($ivSize > 0) {
            $blockSize = $ivSize;
		} else {
            $blockSize = openssl_cipher_iv_length(str_ireplace("-" . $mode, "", $cipher));
		}

		$iv = openssl_random_pseudo_bytes($ivSize);
		$paddingType = $this->padding;

		if ($paddingType != 0 && ($mode == "cbc" || $mode == "ecb")) {
            $padded = $this->padText($text, $mode, $blockSize, $paddingType);
		} else {
        $padded = $text;
		}

		return $iv . openssl_encrypt($padded, $cipher, $encryptKey, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Дешифрование текста
     *
     * @param $text
     * @param $key
     * @return string
     * @throws CryptoPadException
     */
    public function decrypt(string $text, $key = null) : string
    {
        if (!function_exists("openssl_cipher_iv_length")) {
            throw new CryptoPadException("openssl extension is required");
        }

        if ($key === null) {
            $decryptKey = $this->key;
		} else {
            $decryptKey = $key;
		}

        if (empty($decryptKey)) {
            throw new CryptoPadException("Decryption key cannot be empty");
        }

        $cipher = $this->cipher;
		$mode = strtolower(substr($cipher, strrpos($cipher, "-") - strlen($cipher)));

		if (!in_array($cipher, openssl_get_cipher_methods())) {
			throw new CryptoPadException("Cipher algorithm is unknown");
		}

		$ivSize = openssl_cipher_iv_length($cipher);
		if ($ivSize > 0) {
            $blockSize = $ivSize;
		} else {
            $blockSize = openssl_cipher_iv_length(str_ireplace("-" . $mode, "", $cipher));
		}

		$decrypted = openssl_decrypt(substr($text, $ivSize), $cipher, $decryptKey, OPENSSL_RAW_DATA, substr($text, 0, $ivSize));

		$paddingType = $this->padding;

		if ($mode == "cbc" || $mode == "ecb") {
            return $this->unPadText($decrypted, $mode, $blockSize, $paddingType);
		}

		return $decrypted;
    }

    /**
     * Шифрует текст возвращает результат в виде строки base64
     *
     * @param $text
     * @param null $key
     * @param bool $safe
     * @return string
     */
    public function encryptBase64(string $text, $key = null, $safe = false) : string
    {
        if ($safe == true)
            return strtr(base64_encode($this->encrypt($text, $key)), "+/", "-_");

        return base64_encode($this->encrypt($text, $key));
    }

    /**
     * Дешифровать текст, который кодируется в виде строки base64
     *
     * @param $text
     * @param null $key
     * @param bool $safe
     * @return string
     */
    public function decryptBase64(string $text, $key = null, $safe = false) : string
    {
        if ($safe == true)
            return $this->decrypt(base64_decode(strtr($text, "-_", "+/")), $key);

        return $this->decrypt(base64_decode($text), $key);
    }

    /**
     * Возвращает список доступных шифров
     */
    public function getListAvailableCiphers() : array
    {
        return \openssl_get_cipher_methods();
    }
}