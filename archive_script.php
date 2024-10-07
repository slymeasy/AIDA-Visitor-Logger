<?php
// Set the maximum file size in bytes (10 MB)
$maxFileSize = 10 * 1024 * 1024; // 10 MB

// Define paths
$logDir = __DIR__ . '/log';
$logFile = $logDir . '/tracking_log.txt';
$archiveDir = $logDir . '/archive';

// Lock file path
$lockFile = $logDir . '/archive.lock';

// Open or create the lock file
$fpLock = fopen($lockFile, 'c');
if (!$fpLock) {
    // Handle error
    error_log("Cannot open lock file: $lockFile");
    exit;
}

// Acquire an exclusive lock (blocking)
if (!flock($fpLock, LOCK_EX)) {
    // Handle error
    error_log("Cannot acquire lock on file: $lockFile");
    fclose($fpLock);
    exit;
}

// Check if the log file exists
if (!file_exists($logFile)) {
    // Release the lock and exit
    flock($fpLock, LOCK_UN);
    fclose($fpLock);
    exit;
}

// Check the size of the log file
$fileSize = filesize($logFile);
if ($fileSize === false) {
    // Handle error
    error_log("Cannot get file size of: $logFile");
    // Release the lock and exit
    flock($fpLock, LOCK_UN);
    fclose($fpLock);
    exit;
}

if ($fileSize >= $maxFileSize) {
    // Archive the log file

    // Ensure the archive directory exists
    if (!file_exists($archiveDir)) {
        if (!mkdir($archiveDir, 0755, true)) {
            // Handle error
            error_log("Cannot create archive directory: $archiveDir");
            // Release the lock and exit
            flock($fpLock, LOCK_UN);
            fclose($fpLock);
            exit;
        }
    }

    // Create a unique archive filename with date and time
    $dateTime = date('Ymd_His');
    $archivedLogFile = $archiveDir . '/tracking_log_' . $dateTime . '.txt';

    // Move the log file to the archive directory
    if (!rename($logFile, $archivedLogFile)) {
        // Handle error
        error_log("Cannot archive log file to: $archivedLogFile");
        // Release the lock and exit
        flock($fpLock, LOCK_UN);
        fclose($fpLock);
        exit;
    }

    // Logging has stopped; do not create a new log file.

    // Optional: Notify the site owner
    /*
    $to = 'siteowner@example.com';
    $subject = 'Log File Archived and Logging Stopped';
    $message = "The log file has been archived to $archivedLogFile and logging has stopped.";
    mail($to, $subject, $message);
    */
}

// Release the lock
flock($fpLock, LOCK_UN);
fclose($fpLock);
?>
