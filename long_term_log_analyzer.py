# File: python/long_term_log_analyzer.py

import os
import base64
import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import pandas as pd
import matplotlib.pyplot as plt

# Retrieve the ENCRYPTION_KEY from environment variables
ENCRYPTION_KEY_RAW = os.environ.get('ENCRYPTION_KEY')
if ENCRYPTION_KEY_RAW is None:
    raise ValueError('ENCRYPTION_KEY environment variable is not set')

ENCRYPTION_KEY_RAW = ENCRYPTION_KEY_RAW.encode('utf-8')

# Hash the ENCRYPTION_KEY using SHA-256 to derive the key
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(ENCRYPTION_KEY_RAW)
ENCRYPTION_KEY = digest.finalize()

def decrypt_log(encrypted_data):
    try:
        encrypted_bytes = base64.b64decode(encrypted_data)
        iv_len = 16  # AES block size for CBC mode
        iv = encrypted_bytes[:iv_len]
        ciphertext = encrypted_bytes[iv_len:]

        # Use the hashed ENCRYPTION_KEY
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        padding_len = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_len]

        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

class LongTermLogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Long-Term Log Analyzer")
        self.logs = []
        self.dataframe = None

        # UI Elements
        self.upload_button = tk.Button(root, text="Upload Log Files", command=self.upload_files)
        self.upload_button.pack(pady=10)

        self.analyze_button = tk.Button(root, text="Analyze Logs", command=self.analyze_logs)
        self.analyze_button.pack(pady=10)

        self.save_button = tk.Button(root, text="Save Combined Data", command=self.save_combined_data)
        self.save_button.pack(pady=10)

    def upload_files(self):
        file_paths = filedialog.askopenfilenames(title="Select Log Files", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not file_paths:
            return

        for file_path in file_paths:
            with open(file_path, 'r') as f:
                for line in f:
                    decrypted = decrypt_log(line.strip())
                    if decrypted:
                        try:
                            log_entry = json.loads(decrypted)
                            self.logs.append(log_entry)
                        except json.JSONDecodeError:
                            continue

        if self.logs:
            self.dataframe = pd.DataFrame(self.logs)
            self.dataframe['timestamp'] = pd.to_datetime(self.dataframe['timestamp'])
            messagebox.showinfo("Upload Complete", f"Uploaded and processed {len(self.logs)} log entries.")
        else:
            messagebox.showwarning("No Data", "No valid log entries were found.")

    def analyze_logs(self):
        if self.dataframe is None or self.dataframe.empty:
            messagebox.showwarning("No Data", "Please upload log files first.")
            return

        # Time-based Analysis
        self.dataframe['date'] = self.dataframe['timestamp'].dt.date
        daily_visits = self.dataframe.groupby('date').size()

        # Page Performance
        page_visits = self.dataframe['page_url'].value_counts().head(10)

        # Keyword Performance
        keyword_counts = self.dataframe['keyword'].value_counts().head(10)

        # Visualization
        self.visualize_data(daily_visits, page_visits, keyword_counts)

    def visualize_data(self, daily_visits, page_visits, keyword_counts):
        # Plot Daily Visits
        plt.figure(figsize=(10, 6))
        daily_visits.plot(kind='line')
        plt.title('Daily Visits')
        plt.xlabel('Date')
        plt.ylabel('Number of Visits')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

        # Plot Top Pages
        plt.figure(figsize=(10, 6))
        page_visits.plot(kind='bar')
        plt.title('Top 10 Pages')
        plt.xlabel('Page URL')
        plt.ylabel('Number of Visits')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

        # Plot Top Keywords
        plt.figure(figsize=(10, 6))
        keyword_counts.plot(kind='bar')
        plt.title('Top 10 Keywords')
        plt.xlabel('Keyword')
        plt.ylabel('Number of Uses')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

    def save_combined_data(self):
        if self.dataframe is None or self.dataframe.empty:
            messagebox.showwarning("No Data", "No data to save. Please upload log files first.")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".csv", title="Save Combined Data", filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if save_path:
            self.dataframe.to_csv(save_path, index=False)
            messagebox.showinfo("Save Successful", f"Combined data saved to {save_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = LongTermLogAnalyzerApp(root)
    root.mainloop()
