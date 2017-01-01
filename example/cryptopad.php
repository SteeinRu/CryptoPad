<?php
require_once '../src/autoload.php';


//Объявление класса
$crypt = new \SteeinCrypt\CryptoPad();

//Текстовый ключ
$key = 'rUhidagNflImJ3wB';
$global_key = '%31.1e$i86e$f!8jz';

/////////////////////////////////////////////////////////////////////////////////////////

//Стандартная шифрование
$standart_crypt = $crypt->encrypt('example_text', $key);
$crypt->decrypt($standart_crypt, $key);

/////////////////////////////////////////////////////////////////////////////////////////

//Шифруем текст с глобальным ключем
$global_crypt = $crypt
    ->setKey($global_key)
    ->encrypt('example_text2', $key);
$crypt->decrypt($global_crypt, $key);

/////////////////////////////////////////////////////////////////////////////////////////

//Остальные методы шифрования
$encryptBase64 = $crypt->encryptBase64('base64_encrypt', $key, true);
$crypt->decryptBase64($encryptBase64, $key, true);
