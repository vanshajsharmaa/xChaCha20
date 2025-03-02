<?php

class XChaCha20Crypto {
    private const KEY_SIZE = SODIUM_CRYPTO_STREAM_XCHACHA20_KEYBYTES;
    private const NONCE_SIZE = SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES;

    public static function generateKey(): string {
        return random_bytes(self::KEY_SIZE);
    }

    public static function generateNonce(): string {
        return random_bytes(self::NONCE_SIZE);
    }

    public static function encrypt(string $plaintext, string $key, string $nonce): string {
        if (strlen($key) !== self::KEY_SIZE || strlen($nonce) !== self::NONCE_SIZE) {
            throw new Exception("Invalid key or nonce length.");
        }
        $ciphertext = sodium_crypto_stream_xchacha20_xor($plaintext, $nonce, $key);
        return base64_encode($nonce . $ciphertext);
    }

    public static function decrypt(string $encrypted, string $key): string {
        $decoded = base64_decode($encrypted);
        $nonce = substr($decoded, 0, self::NONCE_SIZE);
        $ciphertext = substr($decoded, self::NONCE_SIZE);
        if (strlen($nonce) !== self::NONCE_SIZE) {
            throw new Exception("Invalid encrypted data.");
        }
        return sodium_crypto_stream_xchacha20_xor($ciphertext, $nonce, $key);
    }
}

$key = XChaCha20Crypto::generateKey();
$nonce = XChaCha20Crypto::generateNonce();
$plaintext = "Hello, XChaCha20 in PHP!";

$encrypted = XChaCha20Crypto::encrypt($plaintext, $key, $nonce);
$decrypted = XChaCha20Crypto::decrypt($encrypted, $key);

echo "Original: $plaintext\n";
echo "Encrypted: $encrypted\n";
echo "Decrypted: $decrypted\n";

?>
