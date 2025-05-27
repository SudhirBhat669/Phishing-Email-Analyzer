# Phishing-Email-Analyzer
![Image](https://github.com/user-attachments/assets/17f89773-80c0-47cb-ba4f-e5c82bfc70f2)

# Phishing Email Analyzer with GUI and Machine Learning

# Project Structure
# 📁 phishing-analyzer/
├── phishing_analyzer.py       # Main GUI application
├── README.md                  # Project documentation
├── phishing_report.pdf        # Sample exported report
├── phishing_report.html       # Sample HTML report
├── phishing_email_screenshot.png # Screenshot of phishing email
├── requirements.txt           # Python dependencies

#Objective
To build a GUI-based Python tool that analyzes suspicious emails for phishing characteristics. The tool supports drag-and-drop `.eml` files, scans for threats using rules and machine learning, visualizes WHOIS and URL data, and exports PDF/HTML reports along with screenshots.

# Outcome
Understand common phishing traits and detection tactics.
Gain skills in GUI development using TkinterDnD2.
Apply basic machine learning (Isolation Forest) for email anomaly detection.
Learn to extract and analyze email headers, content, and URLs.
Generate reports to aid in cybersecurity awareness and training.

# Key Concepts
Phishing: Fraudulent email intended to steal sensitive data.
Email Spoofing: Fake sender identity.
Header Analysis: Extracting email source data to find anomalies.
Social Engineering: Psychological tricks in phishing emails.
Threat Detection: Identifying indicators of compromise.
Isolation Forest: Unsupervised ML model for anomaly detection.
WHOIS Lookup: Domain ownership and registration data.

# Features
GUI Dashboard (TkinterDnD2)
Drag & Drop .eml Suspicious Emails
URL Extraction and WHOIS Scan
ML-Based Threat Detection (Isolation Forest)
Export Reports (PDF/HTML/Screenshot)
Indicators like Spoofing, Urgency, Grammar Errors
Incident Log Analyzer
Report Generation of Suspicious Email
Screenshot Capture of Potential Threat

# How It Works
Step 1: Load Suspicious Email
User drags and drops a .eml file into the GUI, and the first 1000 characters are previewed.

Step 2: Feature Extraction
The program extracts suspicious characteristics like:
Unusual or mismatched URLs
Spoofed email addresses
Urgent or manipulative language
Poor grammar/spelling

Step 3: ML Detection
The features are passed to an Isolation Forest model that flags the email as anomalous (likely phishing) or not.

Step 4: URL/Domain Intelligence
URLs are extracted using regular expressions.
WHOIS lookups are performed to see domain registration details.

Step 5: Export Reports
Users can generate:
PDF and 🌐 HTML reports showing phishing indicators
Screenshots for documentation or evidence

# Screenshot Example
> Include a real screenshot file like phishing_email_screenshot.png in your repo.

# Interview Questions
1. What is an email header, and why is it important in phishing analysis?
2. What are common signs of a phishing email?
3. How does the tool detect spoofed email addresses?
4. Why was Isolation Forest used for anomaly detection?
5. What’s the role of WHOIS in phishing analysis?
6. What is the purpose of exporting reports and screenshots?

# Sample Phishing Email Analysis
Spoofing Detected: From: info@micros0ft-support.com
Urgent Language:"Verify your password immediately!"
Bad Grammar:"Your account is has been suspended"
Suspicious Link: http://fake-login.microsoft.verify.com

# Detected as Phishing using ML Anomaly Detection  
Exported report: phishing_report.pdf, phishing_report.html, screenshot.png
