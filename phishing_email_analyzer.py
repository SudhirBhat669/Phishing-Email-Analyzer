import tkinter as tk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD
import os
import pandas as pd
import whois
import requests
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from PIL import ImageGrab
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import datetime
import webbrowser
import re
import tempfile

# --- Machine Learning Setup ---
def train_model():
    data = pd.DataFrame({
        "suspicious_links": [1, 0, 1, 0, 1],
        "spoofing_detected": [1, 0, 0, 0, 1],
        "urgent_language": [1, 1, 0, 0, 1],
        "bad_grammar": [1, 0, 1, 0, 1],
        "label": [1, 0, 1, 0, 1]
    })
    X = data.drop("label", axis=1)
    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(X)
    return model

model = train_model()

# --- Email Analysis Functions ---
def extract_features(email_text):
    features = {
        "suspicious_links": 1 if "http" in email_text and "@" not in email_text else 0,
        "spoofing_detected": 1 if re.search(r"From:.*@(?!yourdomain.com)", email_text) else 0,
        "urgent_language": 1 if re.search(r"urgent|immediately|verify", email_text, re.IGNORECASE) else 0,
        "bad_grammar": 1 if re.search(r"your account is has been", email_text) else 0,
    }
    return pd.DataFrame([features]), features

def generate_pdf_report(features, filename="phishing_report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    c.drawString(100, 750, "Phishing Email Report")
    y = 720
    for k, v in features.items():
        c.drawString(100, y, f"{k.replace('_', ' ').title()}: {'Yes' if v else 'No'}")
        y -= 20
    c.drawString(100, y-20, f"Report generated: {datetime.datetime.now()}")
    c.save()

def export_html_report(features, filename="phishing_report.html"):
    with open(filename, "w") as f:
        f.write("<h1>Phishing Email Report</h1>")
        for k, v in features.items():
            f.write(f"<p><b>{k.replace('_', ' ').title()}:</b> {'Yes' if v else 'No'}</p>")

def analyze_url(url):
    try:
        res = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{url}", timeout=10)
        return res.json()
    except:
        return {"status": "URL Scan failed"}

def analyze_whois(domain):
    try:
        w = whois.whois(domain)
        return str(w)
    except:
        return "WHOIS lookup failed"

def take_screenshot(filename="phishing_email_screenshot.png"):
    image = ImageGrab.grab()
    image.save(filename)

# --- GUI Application ---
class PhishingAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Email Analyzer")
        self.root.geometry("800x600")

        self.label = tk.Label(root, text="Drag & Drop suspicious .eml file here", font=("Arial", 16))
        self.label.pack(pady=20)

        self.drop_area = tk.Text(root, height=10, width=80)
        self.drop_area.pack()
        self.drop_area.drop_target_register(DND_FILES)
        self.drop_area.dnd_bind('<<Drop>>', self.process_file)

        self.analyze_button = tk.Button(root, text="Analyze Email", command=self.analyze)
        self.analyze_button.pack(pady=10)

        self.export_button = tk.Button(root, text="Export Report", command=self.export)
        self.export_button.pack(pady=10)

        self.result_box = tk.Text(root, height=15, width=80)
        self.result_box.pack()

        self.email_text = ""

    def process_file(self, event):
        filepath = event.data.strip('{}')
        if filepath.endswith(".eml"):
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                self.email_text = f.read()
                self.drop_area.delete("1.0", tk.END)
                self.drop_area.insert(tk.END, self.email_text[:1000] + " [Text truncated]")

    def analyze(self):
        if not self.email_text:
            messagebox.showerror("No email loaded", "Please drag and drop a suspicious .eml file first.")
            return

        X, self.features = extract_features(self.email_text)
        pred = model.predict(X)[0]
        anomaly = pred == -1

        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, "Phishing Analysis Result:\n\n")
        for k, v in self.features.items():
            self.result_box.insert(tk.END, f"{k.replace('_', ' ').title()}: {'Yes' if v else 'No'}\n")
        self.result_box.insert(tk.END, f"\nML Anomaly Detected: {'Yes 🚨' if anomaly else 'No ✅'}\n")

        urls = re.findall(r'http[s]?://\S+', self.email_text)
        if urls:
            self.result_box.insert(tk.END, f"\n🔗 Found URLs:\n")
            for url in urls:
                self.result_box.insert(tk.END, f"{url}\n")
                domain = url.split("/")[2]
                whois_data = analyze_whois(domain)
                self.result_box.insert(tk.END, f"WHOIS Info for {domain}:\n{whois_data[:500]}\n...\n\n")

    def export(self):
        generate_pdf_report(self.features)
        export_html_report(self.features)
        take_screenshot()
        messagebox.showinfo("Export Complete", "Report exported to PDF, HTML and Screenshot saved.")

# --- Main ---
if __name__ == "__main__":
    app_root = TkinterDnD.Tk()
    app = PhishingAnalyzerApp(app_root)
    app_root.mainloop()
