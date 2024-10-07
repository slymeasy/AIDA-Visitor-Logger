# Great AIDA Visitor Logger

**Great AIDA Visitor Logger** is a privacy-compliant, lightweight visitor tracking solution that utilizes the AIDA (Attention, Interest, Desire, Action) model to log website visitor interactions. The program captures valuable insights into visitor behavior, such as time spent on each page, referrers, and search keywords, all while ensuring user privacy through anonymized logging and AES-256 encryption.

## Features

- **Visitor Tracking using AIDA Model**: Track visitor engagement and classify it into four stages:
  - Attention: 0-30 seconds
  - Interest: 31-60 seconds
  - Desire: 61-120 seconds
  - Action: 121+ seconds
- **No Cookies or IP Tracking**: Complies with GDPR by not storing any personally identifiable information (PII).
- **Encrypted Logs**: All visitor data is encrypted using AES-256, ensuring secure storage of logs on the server.
- **Log Archiving**: Automatically archives the log file when it reaches a size of 10 MB, moving it to an archive directory without creating a new log file.
- **Long-Term Analysis**: The Python-based GUI provides decryption and analysis of logs over days, weeks, months, and years.
- **Referrer and Keyword Tracking**: Captures where visitors came from (referrer URLs) and any keywords they used to find your website via search engines.

## Components and File Locations

### 1. **Frontend (JavaScript)**

- **aidaTracker.js**: This JavaScript file should be placed in your website’s **frontend/public HTML directory**.
  - For example, you could place it in a `js/` directory and reference it in the HTML `<head>`:
    ```html
    <script src="/js/aidaTracker.js"></script>
    ```
  - The script will automatically track visitor behavior and send the data to the backend when the user leaves the page.

### 2. **Backend (PHP)**

- **track.php**: This file handles receiving the data from the frontend and processing it. Place this file in your website’s **backend directory** (usually in a protected area not accessible via direct URL):
  - Example: `public_html/backend/track.php`
  
- **functions.php**: This file contains reusable functions for the backend operations (e.g., encryption). Place it in the same directory as `track.php` or within a protected directory. You can include this file in `track.php` using PHP’s `include` or `require` function:
  ```php
  require_once 'functions.php';
