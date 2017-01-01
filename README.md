## Steein CryptoPad

This component provides a secure encryption using AES-256-CBC.

**Version PHP** : >= 7.0

```php
$crypto = new \SteeinCrypt\CryptoPad();

//Test key and global key
$key        = 'rUhidagNflImJ3wB';
$global_key = '%31.1e$i86e$f!8jz';

```

### Standard encryption text
```php
$encrypt = $crypto->encrypt('default text', $key);
echo $encrypt;
```

### Standard decryption text
```php
$decrypt = $crypto->decrypt($encrypt, $key);
echo $decrypt;
```

### Encryption and Decryption of text in base64
```php
$encryptBase64 = $crypto->encryptBase64('base64_encrypt', $key, true);
$crypto->decryptBase64($encryptBase64, $key, true);
```

### Encryption using the global key

```php
$global_crypt = $crypto
    ->setKey($global_key)
    ->encrypt('default_text', $key);
$crypto->decrypt($global_crypt, $key);
```



### Support or Contact

* Author: Shamsudin Serderov
* Version Library: 1.0.0
* Email: sourcecode@steein.ru
