<?php
// File: backend/track.php

require 'functions.php';

// Set response header to JSON
header('Content-Type: application/json');

// Get the raw POST data
$input = file_get_contents('php://input');
$data = json_decode($input, true);

if ($data) {
    // Anonymize IP address
    $ip = $_SERVER['REMOTE_ADDR'];
    $visitorID = generateVisitorID($ip);

    // Prepare the log entry
    $logEntry = [
        'visitor_id' => $visitorID,
        'time_spent' => $data['time_spent'],
        'aida_stage' => $data['aida_stage'],
        'referrer' => $data['referrer'],
        'keyword' => $data['keyword'],
        'page_url' => $data['page_url'],
        'timestamp' => date('c') // ISO 8601 format
    ];

    // Convert log entry to JSON
    $logJson = json_encode($logEntry);

    // Encrypt the log entry
    $encryptedLog = encryptData($logJson);

    // Ensure the logs directory exists
    $logDir = __DIR__ . '/../logs/';
    if (!file_exists($logDir)) {
        mkdir($logDir, 0755, true);
    }

    // Save the encrypted log entry to the log file
    $logFile = $logDir . 'tracking_log.txt';
    file_put_contents($logFile, $encryptedLog . PHP_EOL, FILE_APPEND | LOCK_EX);

    // Respond with success
    http_response_code(200);
    echo json_encode(['status' => 'success']);
} else {
    // Invalid data received
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid data received.']);
}
?>
