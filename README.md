
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
- **Long-Term Analysis**: The Python-based GUI provides decryption and analysis of logs over days, weeks, months, and years.
- **Referrer and Keyword Tracking**: Captures where visitors came from (referrer URLs) and any keywords they used to find your website via search engines.

## Components

1. **Frontend (JavaScript)**: The tracking script that runs on your website, capturing visitor behavior and sending it to the backend server.
2. **Backend (PHP)**: A server-side script that receives, processes, and encrypts the visitor data before storing it in log files.
3. **Python Log Analyzer (GUI)**: A desktop application to decrypt and analyze the encrypted logs, providing insights into long-term visitor behavior.

## Installation

### 1. Frontend (JavaScript)
- Place the JavaScript tracking script (`aidaTracker.js`) in the `<head>` section of your website's HTML.
- The script will automatically track visitor behavior and send the data to the backend when the user leaves the page.

### 2. Backend (PHP)
- Place the `track.php` file on your server in a publicly accessible directory (e.g., `https://yourdomain.com/backend/track.php`).
- Ensure that a writable `logs/` directory exists for log file storage.
- Set environment variables for encryption on the server:

  In `.htaccess` (for Apache):
  ```apache
  SetEnv ENCRYPTION_KEY "your-encryption-key"
  SetEnv SALT "your-salt"
  ```

  On other servers, you can set the environment variables in the server configuration.

### 3. Python Log Analyzer
- Install Python 3.x on your machine (if not already installed).
- Install the required libraries:
  ```bash
  pip install cryptography pandas matplotlib tkinter
  ```
- Run the `long_term_log_analyzer.py` script to decrypt and analyze the log files.

## Usage

### Sending Data (Frontend)
- The JavaScript script automatically tracks visitor data and sends a POST request to the PHP backend when the user leaves the page.
- You can manually test the backend with `cURL`:

  ```bash
  curl -X POST https://yourdomain.com/backend/track.php        -H "Content-Type: application/json"        -d "{"time_spent":45,"aida_stage":"Interest","referrer":"https://google.com","keyword":"minimalist lifestyle","page_url":"https://yourdomain.com/minimalism-guide"}"
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

```bash
curl -X POST https://yourdomain.com/backend/track.php      -H "Content-Type: application/json"      -d "{"time_spent":45,"aida_stage":"Interest","referrer":"https://google.com","keyword":"minimalist lifestyle","page_url":"https://yourdomain.com/minimalism-guide"}"
```

## Contributing

Contributions are welcome! Please submit a pull request with detailed information about your changes.

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
