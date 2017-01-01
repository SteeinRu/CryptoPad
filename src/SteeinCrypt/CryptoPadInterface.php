<?php
namespace SteeinCrypt;

/**
 * SteeinCrypt\CryptoPadInterface
 *
 * Интерфейс для SteeinCrypt\CryptoPad
 */
interface CryptoPadInterface
{
    /**
     * Устанавливает алгоритм шифрования
     *
     * @param string $cipher
     * @return $this | CryptoPadInterface
     */
    public function setCipher(string $cipher) : CryptoPadInterface;

    /**
     * Возвращает текущее шифрование
     */
	public function getCipher() : string;

    /**
     * Установка ключа шифрования
     *
     * @param string $key
     * @return CryptoPad
     */
	public function setKey(string $key) : CryptoPad;

    /**
     * Возвращает ключ шифрования
     *
     * @return string
     */
	public function getKey() : string;

    /**
     * Шифрование текста
     *
     * @param $text
     * @param $key
     * @return string
     */
	public function encrypt(string $text, $key = null) : string;

    /**
     * Расшифрование текста
     *
     * @param $text
     * @param $key
     * @return string
     */
	public function decrypt(string $text, $key = null) : string;

    /**
     * Шифрует текст возвращает результат в виде строки base64
     *
     * @param $text
     * @param null $key
     * @param bool $safe
     * @return string
     */
    public function encryptBase64(string $text, $key = null, $safe = false) : string;

    /**
     * Расшифровать текст, который кодируется в виде строки base64
     *
     * @param $text
     * @param null $key
     * @param bool $safe
     * @return string
     */
    public function decryptBase64(string $text, $key = null, $safe = false) : string;

    /**
     * Возвращает список доступных шифров
     */
	public function getListAvailableCiphers() : array;
}