<?php
// File: backend/functions.php

require 'config.php';

/**
 * Generates a unique visitor ID by hashing the IP address with a salt.
 *
 * @param string $ip The visitor's IP address.
 * @return string The generated visitor ID.
 */
function generateVisitorID($ip) {
    return 'User-' . substr(hash('sha256', $ip . SALT), 0, 10);
}

/**
 * Encrypts data using AES-256-CBC.
 *
 * @param string $data The plaintext data to encrypt.
 * @return string The base64-encoded encrypted data.
 */
function encryptData($data) {
    $cipher = 'aes-256-cbc';
    $key = hash('sha256', ENCRYPTION_KEY, true);
    $ivlen = openssl_cipher_iv_length($cipher);
    $iv = openssl_random_pseudo_bytes($ivlen);
    $ciphertext = openssl_encrypt($data, $cipher, $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $ciphertext);
}
?>
