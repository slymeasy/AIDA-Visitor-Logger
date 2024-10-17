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
  ```

- **config.php**: This file should contain configuration settings such as the encryption keys and database connection details (if used). Keep this file in a **secure location**, such as:
  - Example: `public_html/backend/config.php`
  - This file should be referenced in `track.php` and `functions.php` to access configuration settings:
  ```php
  require_once 'config.php';
  ```

### 3. **Log Directory**

- **Log Files**: Logs will be saved in the `public_html/log/` directory.
  - The primary log file is named `tracking_log.txt`, and once it exceeds 10 MB, it is moved to the `archive/` subdirectory:
    - **Log Path**: `public_html/log/tracking_log.txt`
    - **Archived Logs**: `public_html/log/archive/`

### 4. **Python Log Analyzer (Optional)**

- Use the provided Python-based GUI tool to analyze logs offline.
- After downloading the logs, run the Python tool to decrypt and analyze them.

## Installation

### Frontend (JavaScript)

- Place the `aidaTracker.js` file in the frontend directory (e.g., `public_html/js/`).
- Ensure the script is referenced in your HTML `<head>` section.

### Backend (PHP)

1. Place the `track.php`, `functions.php`, and `config.php` files in your backend directory:
   - **track.php**: Handles incoming requests and logs visitor data.
   - **functions.php**: Contains encryption and logging functions.
   - **config.php**: Stores configuration details like the encryption keys.

2. Ensure a writable directory for log files exists at `public_html/log/`.

3. Configure environment variables for encryption in `.htaccess` (for Apache servers):
   ```
   SetEnv ENCRYPTION_KEY "your-encryption-key"
   SetEnv SALT "your-salt"
   ```

4. Ensure the `archive/` directory exists inside the `log/` directory for archived log files.

### Log Archiving (PHP)

- The PHP script automatically archives the `tracking_log.txt` file when it reaches **10 MB**.
- Archived logs are moved to `public_html/log/archive/` and renamed with a timestamp (e.g., `tracking_log_YYYYMMDD_HHMMSS.txt`).
- After archiving, logging will stop until a new `tracking_log.txt` file is manually created.

## Usage

### Sending Data (Frontend)

- The JavaScript script automatically tracks visitor data and sends a POST request to the PHP backend when the user leaves the page.
- You can manually test the backend with `cURL`:
  ```bash
  curl -X POST https://yourdomain.com/backend/track.php \
       -H "Content-Type: application/json" \
       -d "{\"time_spent\":45,\"aida_stage\":\"Interest\",\"referrer\":\"https://google.com\",\"keyword\":\"minimalist lifestyle\",\"page_url\":\"https://yourdomain.com/minimalism-guide\"}"
  ```

### Log Analysis (Python GUI)

- Run the Python Log Analyzer to decrypt logs and analyze visitor behavior:
  ```bash
  python long_term_log_analyzer.py
  ```
- The GUI will allow you to upload encrypted log files, view visitor statistics, and generate long-term reports on visitor engagement.

## Security & Privacy

- **AES-256 Encryption**: All visitor data is encrypted before being stored in the server logs, ensuring data protection.
- **Anonymized Visitor IDs**: Visitor IDs are generated from anonymized IP addresses and additional random components, ensuring GDPR compliance.
- **No Cookies**: The program does not use cookies for tracking, ensuring compliance with privacy-focused browser settings.

## Example cURL Request

To test the backend logging functionality, use the following cURL command:
```
curl -X POST https://yourdomain.com/backend/track.php \
     -H "Content-Type: application/json" \
     -d "{\"time_spent\":45,\"aida_stage\":\"Interest\",\"referrer\":\"https://google.com\",\"keyword\":\"minimalist lifestyle\",\"page_url\":\"https://yourdomain.com/minimalism-guide\"}"
```

## Contributing

Contributions are welcome! Please submit a pull request with detailed information about your changes.

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
