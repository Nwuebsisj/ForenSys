ForenSys - AI-Powered Digital Forensic Toolkit 🛡️
ForenSys is a modern, lightweight digital forensics and incident response (DFIR) tool designed for security analysts and students. It automates the detection of malicious persistence, monitors live network communications, and traces the "Patient Zero" (root cause) of infections using the Gemini 2.5 Flash Lite AI model.

✨ Key Features
1. Persistence Scanner (Registry Analysis)
Scans critical Windows Registry keys (Run/RunOnce) for auto-starting applications.

Cross-references findings with a Local Knowledge Base to minimize false positives (e.g., Microsoft Teams).

Performs PowerShell-based Authenticode Signature checks to verify file integrity.

2. AI Forensic Insight
Integrated with Gemini 2.5 Flash Lite.

Provides real-time, plain-English analysis of "High Risk" files that are unrecognized or unsigned.

Bridges the gap between raw data and actionable intelligence.

3. Patient Zero (Web History Trace)
Extracts and analyzes Chrome Browser history.

Helps investigators identify the original source (URL) of a malicious download or infection.

4. Live Network Monitor
Real-time tracking of established IPv4 and IPv6 connections.

Displays Process IDs (PID), process names, and remote destination addresses.

5. Evidence Preservation
Exports all scan results into a time-stamped CSV report inside the /reports folder.

🚀 Setup Instructions (VS Code + Virtual Environment)
It is highly recommended to use a Virtual Environment (venv).
This keeps the project libraries separate from your global system, preventing version conflicts and ensuring the tool runs exactly as intended.

=======Step-by-Step for VS Code Users:=====================================

After extracting the ZIP file, ensure you have opened the **inner** folder in VS Code so that the structure looks like this:

    ForenSys/
    ├── modules/             # Prototypes and older scanner logic
    ├── ForenSys_Final.py    # THE MAIN APPLICATION
    ├── README.md            # Documentation
    ├── requirements.txt     # List of dependencies
    └── .gitignore           # Security file (hides API keys)

When you download this project as a ZIP from GitHub, the extraction process sometimes creates a "folder inside a folder" (e.g., ForenSys-main/ForenSys-main/).

If your VS Code Terminal cannot find requirements.txt:

Check the top of your VS Code sidebar. If you see two folders with the same name, you are "too far out."

Go to File > Open Folder...

Navigate inside the first folder and select the inner folder that contains the actual .py and .txt files.

Click Select Folder.
=========================================================================================================

1. Open Folder: Open the ForenSys folder in VS Code.

2. Open Terminal: Press Ctrl + ` (backtick) or go to Terminal > New Terminal.

3. Create the VENV: Type the following command and hit Enter: python -m venv .venv

4. Activate the VENV:

        • In the terminal, type: .\.venv\Scripts\activate

5. Set VS Code Interpreter:

        • Press Ctrl + Shift + P.
    
        • Search for "Python: Select Interpreter".
    
        • Select the one labeled ('.venv': venv).

6. Install Requirements: pip install -r requirements.txt
   
7. Getting your Gemini API Key (**Required**)
The AI features require a Google Gemini API Key. It is free for developers:

        • Visit Google AI Studio.
    
        • Sign in with your Google Account.
    
        • Click "Get API key" on the top left.
    
        • Click "Create API key in new project".
    
        • Copy the key.

9. **Run as Admin:** To access the Registry and Network data, VS Code must be running as **Administrator**. 
    Right-click the VS Code icon and select "Run as Administrator" before running the script: 

        • Run the script: python ForenSys_Final.py
    
        • Go to the Settings & Export tab.
    
        • Paste your key into the API Key field.
    
        • Click "Save API Key (Remember Me)".
    
        • Go to the Persistence Scanner and click Run Forensic Scan.

📂 Project Structure

    • ForenSys_Final.py: The main GUI application.

    • requirements.txt: List of Python dependencies.

    • settings.json: Stores your API key locally (created after saving).

    • /reports/: Automatically generated forensic reports.

🛠️ Built With

    • GUI: PySide6 (Qt for Python)

    • AI: Google Generative AI (Gemini 2.5 Flash Lite)

    • System Metrics: psutil

    • Data Processing: Pandas

📝 Disclaimer
This tool is for educational purposes. AI-generated insights should be used as leads for further investigation, not as absolute proof of malice.

        




