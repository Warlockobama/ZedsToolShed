# ZedsToolShed
ZedsToolShed
Welcome to ZedsToolShed! This repository is a collection of tools and scripts designed to enhance workflows for OWASP ZAP (Zed Attack Proxy). These tools assist in automating security assessments, integrating results into reporting platforms like Confluence, and streamlining the penetration testing process.

📌 Features
Automated ZAP Report to Confluence
The zap2confluence.py script extracts security findings from ZAP and formats them into Markdown for documentation in Confluence.
Supports filtering alerts by severity.
Includes optional request/response details for analysis.
Configuration Management
The config.json file allows customization of reporting preferences, including:
API keys and authentication details.
Output format and filtering options.
Integration settings for Confluence.
🚀 Getting Started
1️⃣ Clone the Repository
sh
Copy
Edit
git clone https://github.com/yourusername/ZedsToolShed.git
cd ZedsToolShed
2️⃣ Configure Settings
Modify config.json to match your environment:

json
Copy
Edit
{
    "mode": "report",
    "include_request": true,
    "include_response": true,
    "request_max_length": 5000,
    "response_max_length": 5000,
    "max_instances_per_alert": 6,
    "filter_risk": "all",
    "zap": {
      "base_url": "http://localhost:8080",
      "api_key": "YOUR_ZAP_API_KEY"
    },
    "confluence": {
      "base_url": "https://your-domain.atlassian.net/wiki",
      "space_key": "YOUR_SPACE_KEY",
      "page_title": "Security Assessment Report",
      "username": "your_confluence_username",
      "api_token": "your_confluence_api_token"
    },
    "dry_run": true
}
3️⃣ Run the ZAP to Confluence Script
Ensure you have Python 3.x installed, then run:

sh
Copy
Edit
python3 zap2confluence.py
4️⃣ View Results
If dry_run is set to true, a Markdown report will be generated locally.
If dry_run is false, the report will be uploaded to Confluence.
🛠️ Dependencies
Python 3.x
requests library (pip install requests)
⚠️ Security Considerations
Do NOT hardcode sensitive credentials in config.json. Use environment variables where possible.
The api_key for ZAP should be restricted to authorized users only.
Consider encrypting config.json or using a secrets manager.
📜 License
This repository is licensed under the MIT License. Feel free to modify and use these tools as needed.
