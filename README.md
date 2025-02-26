# ZedsToolShed

A collection of tools and scripts designed to enhance workflows for OWASP ZAP (Zed Attack Proxy). These tools assist in automating security assessments, integrating results into reporting platforms like Confluence, and streamlining the penetration testing process.

## 🛠️ Key Features

### ZAP to Confluence Integration
The `zap2confluence.py` script automates the process of extracting security findings from ZAP scans and formatting them for documentation in Confluence.

- **Customizable Reporting**: Generate both full assessment reports and knowledge base updates
- **Advanced Filtering**: Filter alerts by severity level (High, Medium, Low, Informational)
- **Rich Context**: Includes request/response details with configurable truncation
- **Discovery Statistics**: Automatically calculates and reports on application attack surface metrics

### Knowledge Base Management
The included `kb.go` script provides a comprehensive knowledge base system for tracking and triaging security findings over time.

- **Alert Tracking**: Maintain historical records of security findings across multiple scans
- **Canonical Vulnerability Database**: Reference comprehensive details about each ZAP alert type
- **Multiple Export Formats**: Support for both Confluence HTML and Obsidian Markdown
- **Project Organization**: Group findings by project for easier management

## 📋 Installation & Setup

### Prerequisites
- Python 3.x
- Go 1.23+ (for KB management)
- OWASP ZAP instance (running locally or remotely)
- Confluence instance (if using the integration features)

### Quick Start

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/ZedsToolShed.git
   cd ZedsToolShed
   ```

2. **Configure Settings**
   Copy the example configuration and customize it for your environment:
   ```bash
   cp config.json.example config.json
   ```
   
   Edit `config.json` to match your specific needs:
   ```json
   {
     "mode": "report",
     "include_request": true,
     "include_response": true,
     "request_max_length": 5000,
     "response_max_length": 5000,
     "max_instances_per_alert": 6,
     "filter_risk": "medium+",
     "zap": {
       "base_url": "http://localhost:8080",
       "api_key": "YOUR_ZAP_API_KEY"
     },
     "confluence": {
       "base_url": "https://your-domain.atlassian.net/wiki",
       "space_key": "YOUR_SPACE_KEY",
       "page_title": "ZAP Scan Report",
       "username": "your_confluence_username",
       "api_token": "your_confluence_api_token"
     },
     "dry_run": true
   }
   ```

3. **Run the ZAP to Confluence Script**
   ```bash
   python3 zap2confluence.py
   ```

4. **Initialize the Knowledge Base** (Optional)
   ```bash
   go run kb.go --initialize --format obsidian --output ./kb
   ```

## 📊 Usage Examples

### Generate a Security Assessment Report
```bash
# Set mode to "report" in config.json, then run:
python3 zap2confluence.py
```

### Create a Knowledge Base Update
```bash
# Set mode to "kb" in config.json, then run:
python3 zap2confluence.py
```

### Import ZAP Findings to Knowledge Base
```bash
go run kb.go --update --input scan_results.json --project "Web Application" --format confluence
```

## ⚙️ Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `mode` | Output format (`report` or `kb`) | `report` |
| `include_request` | Include HTTP request details | `true` |
| `include_response` | Include HTTP response details | `true` |
| `filter_risk` | Filter alerts by risk level (`all`, `high+`, `medium+`, `low+`) | `medium+` |
| `dry_run` | Generate output file without publishing to Confluence | `true` |

## 🔒 Security Considerations

- **API Key Protection**: Never hardcode sensitive credentials in `config.json`. Use environment variables where possible.
- **Access Control**: Restrict ZAP API key access to authorized users only.
- **Credentials Management**: Consider using a secrets manager instead of storing API tokens in config files.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
