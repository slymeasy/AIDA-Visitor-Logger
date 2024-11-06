# File: python/log_analyzer.py

import os
import base64
import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes  # Import hashes
from cryptography.hazmat.backends import default_backend
import pandas as pd

# Define a list of visitor IDs to ignore
IGNORE_VISITOR_IDS = [
    'visitor_id_1',
    'visitor_id_2',
    'visitor_id_3',
    # Add more IDs as needed
]

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

class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Analyzer")
        self.logs = []

        # UI Elements
        self.upload_button = tk.Button(root, text="Upload Log Files", command=self.upload_files)
        self.upload_button.pack(pady=10)

        self.tree = ttk.Treeview(root, columns=("Visitor ID", "Time Spent", "AIDA Stage", "Referrer", "Keyword", "Page URL", "Timestamp"), show='headings')
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, anchor='center')
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.analyze_button = tk.Button(root, text="Analyze Logs", command=self.analyze_logs)
        self.analyze_button.pack(pady=10)

    def upload_files(self):
        file_paths = filedialog.askopenfilenames(title="Select Log Files", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not file_paths:
            return

        ignored_count = 0  # Counter for ignored entries

        for file_path in file_paths:
            with open(file_path, 'r') as f:
                for line in f:
                    decrypted = decrypt_log(line.strip())
                    if decrypted:
                        try:
                            log_entry = json.loads(decrypted)
                            visitor_id = log_entry.get('visitor_id', 'n/a')
                            
                            # Check if the visitor_id is in the ignore list
                            if visitor_id in IGNORE_VISITOR_IDS:
                                ignored_count += 1
                                continue  # Skip this entry

                            self.logs.append(log_entry)
                            self.tree.insert("", "end", values=(
                                visitor_id,
                                log_entry.get('time_spent', 'n/a'),
                                log_entry.get('aida_stage', 'n/a'),
                                log_entry.get('referrer', 'n/a'),
                                log_entry.get('keyword', 'n/a'),
                                log_entry.get('page_url', 'n/a'),
                                log_entry.get('timestamp', 'n/a')
                            ))
                        except json.JSONDecodeError:
                            continue

        total_uploaded = len(file_paths)
        total_logs = len(self.logs)
        messagebox.showinfo(
            "Upload Complete",
            f"Uploaded {total_uploaded} files with {total_logs} log entries.\n"
            f"Ignored {ignored_count} entries based on visitor ID."
        )

    def analyze_logs(self):
        if not self.logs:
            messagebox.showwarning("No Data", "No logs to analyze.")
            return

        df = pd.DataFrame(self.logs)

        # Total Visits
        total_visits = len(df)

        # AIDA Breakdown
        aida_counts = df['aida_stage'].value_counts().to_dict()

        # Referrer Statistics
        referrer_counts = df['referrer'].value_counts().head(10).to_dict()

        # Keyword Statistics
        keyword_counts = df['keyword'].value_counts().head(10).to_dict()

        # Display Results
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title("Analysis Report")

        report = f"Total Visits: {total_visits}\n\nAIDA Breakdown:\n"
        for stage, count in aida_counts.items():
            report += f"  {stage}: {count}\n"

        report += "\nTop Referrers:\n"
        for ref, count in referrer_counts.items():
            report += f"  {ref}: {count}\n"

        report += "\nTop Keywords:\n"
        for kw, count in keyword_counts.items():
            report += f"  {kw}: {count}\n"

        tk.Label(analysis_window, text=report, justify=tk.LEFT, padx=10, pady=10).pack()

        # Optional: Add visualization if matplotlib is installed
        self.visualize_aida_breakdown(aida_counts)

    def visualize_aida_breakdown(self, aida_counts):
        try:
            import matplotlib.pyplot as plt

            stages = list(aida_counts.keys())
            counts = list(aida_counts.values())

            plt.figure(figsize=(8,6))
            plt.bar(stages, counts, color='skyblue')
            plt.xlabel('AIDA Stages')
            plt.ylabel('Number of Visitors')
            plt.title('Visitor Breakdown by AIDA Stage')
            plt.show()
        except ImportError:
            messagebox.showwarning("Matplotlib Not Installed", "Install matplotlib to enable visualization.")

if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerApp(root)
    root.mainloop()
