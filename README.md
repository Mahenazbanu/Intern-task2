task2.py - Phishing Email Analyzer v2
(note : task.py is a basic version of this.)
Phishing Email Analyzer  is a robust and production-ready tool designed to analyze .eml email files for potential phishing attempts. This script performs deep inspection of email headers, body content, attachments, and links to detect spoofing, suspicious URLs, urgency triggers, grammar issues, and more. 
🔍 Features 

    Sender Analysis : Detects sender spoofing using DMARC/SPF checks and header inconsistencies.
    Content Inspection : Identifies shortened or malicious URLs, IP-based domains, and executable downloads.
    Urgency Detection : Flags emails with urgent language commonly used in phishing attacks.
    Grammar & Spelling Check : Uses advanced grammar checking to flag poorly written emails.
    Attachment Scanning : Detects potentially dangerous file types like .exe, .js, etc.
    Risk Assessment : Calculates risk levels (Low, Medium, High, Critical) based on weighted findings.
    PDF Report Generation : Generates a detailed PDF report with all analysis results.
    Email Reporting : Optionally sends the PDF report via SMTP to a designated recipient.
     

🧰 Requirements 

Ensure you have the following dependencies installed: 
pip install fpdf2 pyyaml requests language-tool-python beautifulsoup4
 
 

For PDF generation with custom fonts, also install: 
 sudo apt install -y fonts-dejavu  # Linux
 
 

or manually place a copy of DejaVuSans.ttf in the working directory. 
🛠️ Configuration 

    Create a config.yaml file for analyzer settings (optional).
    Set SMTP credentials using environment variables:
    
    bash:
1.export SMTP_HOST=your.smtp.server
2.export SMTP_PORT=587
3.export SMTP_USER=your@email.com
4.export SMTP_PASSWORD=yourpassword
 
 
Customize trusted domains inside the script:
python
  TRUSTED_DOMAINS = ["yourcompany.com"]
     
     
     

📁 Usage 
Analyze an Email File 
bash:
python phishing_analyzer.py sample_email.eml
 
 
Generate Report and Send via Email 
bash:
python phishing_analyzer.py sample_email.eml --send-to analyst@example.com
 
 
Verbose Output 
bash:
python phishing_analyzer.py sample_email.eml --verbose
 
 
📎 Example Output 

After running the analyzer, you'll get a PDF report named like: 
phishing_report_20240615_123456.pdf
 
 

The report includes: 

    Risk level assessment
    Sender analysis
    Suspicious links
    Urgency indicators
    Grammar issues
    Attachment warnings
     

📦 Project Structure : -
phishing-analyzer/
├── phishing_analyzer.py     # Main script
├── config.yaml              # Optional configuration
├── company_logo.png         # Optional logo for reports
└── DejaVuSans.ttf           # Optional font for PDFs
 
 
📝 License 

This project is licensed under the MIT License – see the LICENSE  file for details. 
✅ Contributing 

Contributions are welcome! Please read our contributing guidelines  for more info. 
❓ Support / Issues 

If you encounter any bugs or have feature suggestions, please open an issue on GitHub. 
