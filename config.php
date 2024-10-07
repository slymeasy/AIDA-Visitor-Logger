<?php
// File: backend/config.php

// Retrieve the encryption key and salt from environment variables
define('ENCRYPTION_KEY', getenv('ENCRYPTION_KEY'));
define('SALT', getenv('SALT'));

// Check if the encryption key and salt are set
if (!ENCRYPTION_KEY || !SALT) {
    error_log('Encryption key and salt must be set in environment variables.');
    exit('Configuration error. Please contact the administrator.');
}
?>
